# Gate SDK

Middleware Express para integrar autenticación de [Gate](https://github.com/dcanje/gate) en aplicaciones internas de Apprecio/Dcanje.

Gate maneja la autenticación (Google OAuth) y autorización (RBAC con permisos granulares). Este SDK implementa el flujo **OAuth 2.0 Authorization Code Flow** completo + protección **state CSRF**: el JWT nunca aparece en una URL ni en logs.

## Instalación

```bash
# Última versión de main
npm install git+https://github.com/dcanje/gate-sdk.git

# Fijar una versión específica (recomendado para reproducibilidad)
npm install gate-sdk@github:dcanje/gate-sdk#v3.0.1
```

## Uso rápido

```javascript
const express = require('express');
const { createGateMiddleware } = require('gate-sdk');

async function arrancar() {
  const app = express();

  // Cloud Run termina TLS en su frontend y proxea HTTP plano al contenedor.
  // Sin esto el callback queda con scheme http y Gate rechaza la redirección.
  app.set('trust proxy', true);

  const gate = await createGateMiddleware({
    appId: process.env.GATE_APP_ID,
    gateUrl: process.env.GATE_URL,
    appSecret: process.env.GATE_APP_SECRET,
    bypass: process.env.GATE_DISABLED === 'true',
  });

  app.use(gate);

  app.get('/', (req, res) => {
    res.json({ hola: req.user.email, permisos: req.user.permissions });
  });

  app.listen(8080);
}

arrancar().catch((err) => {
  console.error('No se pudo arrancar:', err);
  process.exit(1);
});
```

**Importante:** `createGateMiddleware` es **async** desde v2.0. Si no le pasas `publicKey`, la descarga al boot desde `{gateUrl}/auth/public-key`. Si la descarga falla, lanza y el server no arranca (fail-fast).

## Configuración

| Opción | Tipo | Default | Descripción |
|---|---|---|---|
| `appId` | String | — | **Requerido** (salvo `bypass: true`). Slug de la app registrada en Gate. |
| `gateUrl` | String | — | **Requerido** (salvo `bypass: true`). URL base del servicio Gate. |
| `appSecret` | String | — | **Requerido** (salvo `bypass: true`). Shared secret de la app — se usa para el intercambio server-to-server del code por el JWT. **NUNCA lo expongas al frontend ni lo commitees**: solo el server de la app debe tenerlo. |
| `publicKey` | String | (descarga) | Clave pública RSA de Gate (PEM). Si no se pasa, el SDK la descarga automáticamente desde `{gateUrl}/auth/public-key` al boot. |
| `bypass` | Boolean | `false` | Si `true`, retorna un middleware noop que setea `req.user = { isRoot: true, email: '_local', ... }`. Útil para desarrollo local sin Gate. No usar en producción. |
| `validateWithGate` | Boolean | `true` | Consultar `/auth/validate` de Gate para detectar tokens invalidados (cambios de rol, desactivación, etc.). |
| `cacheTtl` | Number | `60000` | Duración del cache de validación en ms (60s). `0` = sin cache. |
| `failOpenOnNetworkError` | Boolean | `false` | **Seguridad vs disponibilidad.** Default `false`: si Gate no responde, retorna 503 y preserva la garantía de revocación inmediata. `true`: permite pasar con solo firma JWT válida (defeats tokenVersion). |

## Fail-fast: configuración incompleta = no arranca

Si `appId`, `gateUrl` o `appSecret` están vacíos y no pasaste `bypass: true`, el SDK lanza:

```
Error: createGateMiddleware: appId, gateUrl y appSecret son requeridos. Para bypass de desarrollo, pasar { bypass: true }.
```

Esto evita que un deploy con variables mal configuradas termine sirviendo tráfico abierto sin auth. Para desarrollo local sin Gate, opta explícitamente por bypass:

```javascript
const gate = await createGateMiddleware({ bypass: true });
```

## El flujo (OAuth 2.0 Authorization Code Flow + state CSRF)

```
1. User abre /dashboard sin token
        │
        ▼
2. SDK: no hay cookie gate_token
   - genera state = randomBytes(32).toString('hex')
   - setea cookie gate_state=<state>; HttpOnly; Max-Age=600
   - redirige 302 a Gate:
     /login?app=mi-app&callback=https://app/dashboard&state=<state>
        │
        ▼
3. Gate muestra login Google. User autentica.
        │
        ▼
4. Gate emite code single-use de 60s
        │
        ▼
5. Gate redirige al callback:
   https://app/dashboard?code=<code>&state=<state>
        │
        ▼
6. SDK detecta ?code= y ?state=:
   - lee cookie gate_state
   - compara con req.query.state usando crypto.timingSafeEqual
   - si no coincide (mismatch / cookie ausente):
       · navegación browser → borra la cookie state y redirige a la URL
         base limpia para rearmar el login (recuperación, ver más abajo)
       · petición no-HTML → 400 "state CSRF: ..."
        │
        ▼
7. SDK hace POST server-to-server:
   POST {gateUrl}/auth/exchange-code
   Body: { code, app: appId, secret: appSecret }
        │
        ▼
8. Gate valida el code (existe, no usado, no expirado, appId matchea,
   secret matchea timing-safe), marca usado, emite JWT firmado
        │
        ▼
9. Gate responde 200 { token: <jwt>, expiresIn: 14400 }
   (el JWT viaja por el body de un POST, NO por una URL)
        │
        ▼
10. SDK:
    - setea cookie gate_token=<jwt>; HttpOnly; Max-Age=expiresIn
    - borra cookie gate_state
    - Cache-Control: no-store; Referrer-Policy: no-referrer
    - redirect 302 a /dashboard (URL completamente limpia, sin code ni state)
        │
        ▼
11. Browser navega a /dashboard con cookie gate_token
        │
        ▼
12. SDK lee cookie, valida JWT, req.user disponible, next()
```

### Garantías de seguridad del flujo

- **JWT nunca en URL**: solo viaja por POST server-to-server (paso 9) y en cookies httpOnly que el JS no puede leer. No aparece en barra de direcciones, history del browser, logs del proxy, ni Referer.
- **State CSRF**: el state vincula la petición inicial al callback. Un atacante con un code o JWT propio no puede forzar a la víctima a usarlo, porque no puede setear cookies en el browser de la víctima para el dominio de la app.
- **Single-use codes**: cada code es usable una sola vez. Replay attacks bloqueados.
- **Codes con TTL corto** (60s): ventana mínima entre emisión y consumo.
- **Secret nunca en frontend**: el `appSecret` solo vive en el server de la app.
- **Cookies con `Secure`** automático cuando `req.protocol === 'https'` o `X-Forwarded-Proto: https` (Cloud Run).
- **Path del redirect normalizado** con regex `^[/\\]+` para evitar open redirect via protocol-relative URL (`//evil.com/...`) o backslash injection.

## req.user

Después del middleware (modo real), `req.user` contiene:

```javascript
{
  email: 'usuario@apprecio.com',
  name: 'Nombre Completo',
  picture: 'https://...',
  isRoot: false,
  role: 'vendedor',
  appId: 'cotizador-divisas',
  permissions: ['view:dashboard', 'edit:reportes'],
}
```

En modo bypass (`bypass: true`):

```javascript
{
  email: '_local',
  name: 'Local Bypass',
  isRoot: true,
  role: 'admin',
  permissions: [],
  appId: '_local',
}
```

## requirePermission y requireRole

```javascript
const { requirePermission, requireRole } = require('gate-sdk');

// Recomendado: chequear por permiso, no por rol.
app.get('/reportes', requirePermission('view:reportes'), handler);
app.post('/usuarios', requirePermission('manage:usuarios'), handler);

// Múltiples permisos: deben estar todos.
app.delete('/empresa/:id', requirePermission('manage:empresas', 'delete:empresas'), handler);

// Por rol (legacy o cuando el modelo de permisos no sirve).
app.get('/ventas', requireRole('vendedor', 'supervisor'), handler);
```

**`isRoot: true` salta todos los chequeos** — no hace falta listar root en `requireRole`/`requirePermission`.

Convención de nombres de permisos: `acción:sección` (`view:dashboard`, `edit:reportes`, `manage:usuarios`). Cada app define los suyos y el mapeo rol → permisos en su registro en Gate.

## HTML vs no-HTML: redirect o 401 JSON

Cuando llega una request sin token:

- **`Accept: text/html`** (browser navegando): el SDK responde **302 redirect** a `/login?app=<appId>&callback=<url>&state=<state>` de Gate.
- **Cualquier otro `Accept`** (fetch, curl, llamadas de SPA): el SDK responde **401 JSON** con `{ error: 'No autenticado', loginUrl: '...' }`. Tu cliente puede leer `loginUrl` y redirigir manualmente cuando le venga bien.

En ambos casos la cookie `gate_state` queda seteada para que un siguiente navigate del browser pueda completar el flow.

## Recuperación de callbacks obsoletos (desde v3.0.1)

Un callback `?code=&state=` puede llegar **obsoleto**: la cookie `gate_state` ya no existe (caducó a los 10 min) o quedó pisada por un state más nuevo. El caso típico real es una pestaña abierta con polling: cuando el token expira, cada request regenera la cookie `gate_state`, así que al completar un re-login el `state` del callback ya no calza con la cookie → `state CSRF: mismatch`.

Antes esto terminaba en un **JSON 400 sin salida**. Desde v3.0.1, ante `mismatch` o `cookie ausente`:

- **`Accept: text/html`** (navegación de browser): el SDK **borra la cookie `gate_state` stale y redirige 302 a la URL base limpia** (sin `code`/`state`). El siguiente request, ya sin token, arranca un login fresco. El usuario se recupera solo, sin ver el error.
- **Cualquier otro `Accept`** (API/SPA): se mantiene el **400 JSON** con `state CSRF: ...` (contrato intacto).

Es seguro: el `code` nunca se canjea cuando el state no calza, así que no hay session fixation; solo le damos al usuario legítimo un camino de vuelta. El path del redirect se normaliza igual que en el flujo exitoso (anti open-redirect).

**Recomendación para apps con polling/long-running:** maneja el `401` en tus llamadas `fetch` —detén el polling y redirige a `loginUrl`— para que una pestaña vieja no quede regenerando la cookie `gate_state` indefinidamente.

## Variables de entorno

```env
GATE_URL=https://gate.tu-empresa.com
GATE_APP_ID=mi-aplicacion
GATE_APP_SECRET=<hex64 generado al registrar la app en Gate>
GATE_DISABLED=false
# Opcional: si no se setea, se descarga al boot desde {GATE_URL}/auth/public-key.
# GATE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
```

## Modo bypass (desarrollo local sin Gate)

```javascript
const gate = await createGateMiddleware({
  bypass: process.env.GATE_DISABLED === 'true',
  // appId, gateUrl y appSecret pueden quedar vacíos cuando bypass=true
  appId: process.env.GATE_APP_ID,
  gateUrl: process.env.GATE_URL,
  appSecret: process.env.GATE_APP_SECRET,
});
```

`req.user` queda con `isRoot: true` y todos los chequeos pasan. Si `bypass` es falso pero las vars están vacías, el SDK lanza al boot — no hay forma de arrancar accidentalmente sin auth en prod.

## Invalidación inmediata de tokens

Por defecto, el SDK consulta a Gate para verificar que el token no ha sido invalidado (token versioning). Si un admin cambia roles, permisos o desactiva un usuario en Gate, el token se invalida **inmediatamente** en el panel admin y en **máximo 60s** en las apps consumidoras (configurable con `cacheTtl`).

Si Gate está caído (error de red/timeout), por default el SDK devuelve **503 Service Unavailable** en vez de dejar pasar silenciosamente. Esto preserva la garantía de revocación inmediata.

```javascript
const { clearValidationCache } = require('gate-sdk');
clearValidationCache();
```

## Migración v2 → v3

v3 es **breaking change** (sumamos `appSecret` requerido + flow cambió de token-in-URL a code+exchange).

| v2.x | v3.x |
|---|---|
| `await createGateMiddleware({ appId, gateUrl, publicKey })` | `await createGateMiddleware({ appId, gateUrl, appSecret, publicKey? })` |
| Sin `appSecret` | **`appSecret` requerido** (sin él, lanza al boot) |
| GATE redirigía al callback con `?gate_token=<JWT>` (JWT en URL) | GATE redirige con `?code=<code>&state=<state>` (code + state) |
| SDK extraía JWT del query a cookie | SDK valida state vs cookie, hace POST server-to-server, recibe JWT en body |
| `/login?app=X&callback=Y` sin state | `/login?app=X&callback=Y&state=Z` |
| Sin protección CSRF en el flow de login | Cookie `gate_state` httpOnly comparada timing-safe con `?state=` del callback |

**Pasos para migrar:**

1. Conseguir el `secret` de tu app desde el panel admin de Gate (pestaña Configuración de la app).
2. Agregar `GATE_APP_SECRET=<el-secret>` al `.env` de tu app.
3. Bumpear la versión del SDK: `"gate-sdk": "github:dcanje/gate-sdk#v3.0.0"`. Correr `npm install`.
4. Pasar `appSecret` al `createGateMiddleware`.
5. Probar localmente — el flow completo se ejecuta sin cambios en el código de la app.

## Más información

- [Gate — Servicio de autenticación](https://github.com/dcanje/gate)
- Para registrar tu app en Gate, contacta al administrador.
