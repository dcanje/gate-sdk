# Gate SDK

Middleware Express para integrar autenticación de [Gate](https://github.com/dcanje/gate) en aplicaciones internas de Apprecio/Dcanje.

Gate maneja la autenticación (Google OAuth) y autorización (RBAC con permisos granulares). Este SDK valida los tokens JWT que Gate emite, expone `req.user` con la información del usuario autenticado, y se encarga del flujo completo del callback (cookie httpOnly, redirect limpio, normalización de path, etc.) sin que las apps tengan que escribir wrappers.

## Instalación

```bash
# Última versión de main
npm install git+https://github.com/dcanje/gate-sdk.git

# Fijar una versión específica (recomendado para reproducibilidad)
npm install gate-sdk@github:dcanje/gate-sdk#v2.0.1
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
| `publicKey` | String | (descarga) | Clave pública RSA de Gate (PEM). Si no se pasa, el SDK la descarga automáticamente desde `{gateUrl}/auth/public-key` al boot. |
| `bypass` | Boolean | `false` | Si `true`, retorna un middleware noop que setea `req.user = { isRoot: true, email: '_local', ... }`. Útil para desarrollo local sin Gate. No usar en producción. |
| `validateWithGate` | Boolean | `true` | Consultar `/auth/validate` de Gate para detectar tokens invalidados (cambios de rol, desactivación, etc.). |
| `cacheTtl` | Number | `60000` | Duración del cache de validación en ms (60s). `0` = sin cache. |
| `failOpenOnNetworkError` | Boolean | `false` | **Seguridad vs disponibilidad.** Default `false`: si Gate no responde, retorna 503 y preserva la garantía de revocación inmediata. `true`: permite pasar con solo firma JWT válida (defeats tokenVersion). |

## Fail-fast: configuración incompleta = no arranca

Si `appId` o `gateUrl` están vacíos y no pasaste `bypass: true`, el SDK lanza:

```
Error: createGateMiddleware: appId y gateUrl son requeridos. Para bypass de desarrollo, pasar { bypass: true }.
```

Esto evita que un deploy con variables mal configuradas (típicamente Cloud Run sin el `.env.yaml` cargado) termine sirviendo tráfico abierto sin auth. Para desarrollo local sin Gate, opta explícitamente por bypass:

```javascript
const gate = await createGateMiddleware({ bypass: true });
```

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

## Comportamiento del callback (lo que el SDK hace por ti)

Cuando Gate redirige al usuario a tu app con `?gate_token=<JWT>`, **el SDK se encarga de todo**:

1. **Verifica la firma del JWT** antes de hacer nada más. Si el JWT es inválido o está expirado, responde 401 sin tocar la sesión (anti session fixation con tokens fabricados).
2. **Guarda el JWT en cookie httpOnly** (`gate_token`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` automáticamente si la request viene por HTTPS o por `X-Forwarded-Proto: https`).
3. **Redirige 302 a la misma URL sin el query** `gate_token`, con headers `Cache-Control: no-store` y `Referrer-Policy: no-referrer`. Así el JWT no queda en la barra de direcciones, el history del navegador, los logs del proxy/Cloud Run, ni el `Referer` que enviarías a un recurso externo (fonts, CDN, avatares).
4. **Normaliza el path del redirect** con regex `^[/\\]+` para evitar open redirect via protocol-relative URL (`//evil.com/...`) o backslash injection.
5. **Inyecta `Authorization: Bearer <JWT>` desde la cookie** en requests siguientes que no traigan el header, así fetches desde tu SPA pasan autenticados sin que tengas que tocar el cliente JS.

**Antes (v1.x), cada app tenía que reimplementar todo esto en un wrapper.** Si tu app tiene un wrapper local (`gateAuth.js`, `src/middleware/auth.js`, etc.) que hace cookie/redirect/sanitize/401-JSON, **bórralo** — el SDK ya lo hace.

## HTML vs no-HTML: redirect o 401 JSON

Cuando llega una request sin token:

- **`Accept: text/html`** (browser navegando): el SDK responde **302 redirect** a `/login?app=<appId>&callback=<url>` de Gate.
- **Cualquier otro `Accept`** (fetch, curl, llamadas de SPA): el SDK responde **401 JSON** con `{ error: 'No autenticado', loginUrl: '...' }`. Tu cliente puede leer `loginUrl` y redirigir manualmente cuando le venga bien (típicamente en un interceptor).

Esto evita el patrón roto de "fetch que recibe HTML del login en vez de JSON" y permite que SPAs y APIs convivan en el mismo middleware.

## Variables de entorno

```env
GATE_URL=https://gate.tu-empresa.com
GATE_APP_ID=mi-aplicacion
GATE_DISABLED=false
# Opcional: si no se setea, se descarga al boot desde {GATE_URL}/auth/public-key.
# GATE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
```

## Flujo completo

```
Usuario abre /reportes en tu app sin token
        │
        ▼
gate-sdk no encuentra token (header ni cookie)
        │
        ▼
Redirige a Gate: /login?app=mi-app&callback=https://mi-app.com/reportes
        │
        ▼
Usuario hace Google Sign-In
        │
        ▼
Gate redirige de vuelta: https://mi-app.com/reportes?gate_token=JWT
        │
        ▼
gate-sdk verifica firma RS256 + valida con Gate (tokenVersion)
        │
        ▼
Guarda cookie httpOnly + redirect 302 a /reportes (sin query)
        │
        ▼
Browser navega a /reportes con cookie en el jar
        │
        ▼
gate-sdk lee cookie, inyecta Authorization, req.user disponible
        │
        ▼
Tu handler corre con req.user.email / role / permissions
```

## Modo bypass (desarrollo local sin Gate)

Para correr tu app sin Gate (típico para devs iterando sin VPN):

```javascript
const gate = await createGateMiddleware({
  bypass: process.env.GATE_DISABLED === 'true',
  // appId y gateUrl pueden quedar vacíos cuando bypass=true
  appId: process.env.GATE_APP_ID,
  gateUrl: process.env.GATE_URL,
});
```

`req.user` queda con `isRoot: true` y todos los chequeos pasan. Si `bypass` es falso pero las vars están vacías, el SDK lanza al boot — no hay forma de arrancar accidentalmente sin auth en prod.

## Invalidación inmediata de tokens

Por defecto, el SDK consulta a Gate para verificar que el token no ha sido invalidado (token versioning). Si un admin cambia roles, permisos o desactiva un usuario en Gate, el token se invalida **inmediatamente** en el panel admin y en **máximo 60s** en las apps consumidoras (configurable con `cacheTtl`).

Si Gate está caído (error de red/timeout), por default el SDK devuelve **503 Service Unavailable** en vez de dejar pasar silenciosamente. Esto preserva la garantía de revocación inmediata: un token revocado por tokenVersion NO puede usarse si el middleware no puede verificar contra Gate. Para apps que prioricen disponibilidad sobre revocación inmediata, agregar `failOpenOnNetworkError: true`.

Si Gate responde 401 explícitamente, el token se rechaza en todos los casos.

Para desactivar la validación contra Gate (no recomendado en producción):

```javascript
await createGateMiddleware({ ..., validateWithGate: false });
```

### Limpiar cache manualmente

```javascript
const { clearValidationCache } = require('gate-sdk');
clearValidationCache();
```

## Migración v1 → v2

v2 es **breaking change**:

| v1.x | v2.x |
|---|---|
| `const gate = createGateMiddleware({...})` síncrono | `const gate = await createGateMiddleware({...})` async |
| `publicKey` requerida | `publicKey` opcional (se descarga si no se pasa) |
| Si faltan vars: bypass silencioso con warn | Si faltan vars y no hay `bypass: true`: lanza |
| Apps con wrapper para cookie/redirect/sanitize/401-JSON | El SDK lo hace, **borra el wrapper** |
| `gateAppId`, `gatePublicKey`, `gateDisabled` (nombres del wrapper) | `appId`, `publicKey`, `bypass` (nombres del SDK) |

**Pasos para migrar:**

1. Bumpea la versión del SDK en tu `package.json`: `"gate-sdk": "github:dcanje/gate-sdk#v2.0.1"`. Corre `npm install`.
2. Convierte el bootstrap en async (`async function arrancar() { ... }`).
3. Sustituye llamadas al wrapper local por `createGateMiddleware` directo del SDK con los nombres nuevos de opciones.
4. **Borra tu wrapper local** (`gateAuth.js`, `src/middleware/auth.js`, etc.).
5. **Borra los tests del wrapper local** (el SDK tiene su propia suite que cubre todo).
6. Si tu app necesita lógica específica post-auth (ej. inyectar campos extra a `req.user`), agrega un middleware pequeño después del `gate`, no antes.

Ejemplos reales:
- [`emisor-bte-sii`](https://github.com/dcanje/emisor-bte-sii) — migración completa, `servidor.js` ahora monta `createGateMiddleware` directo.
- [`panel-reportes-giftcard`](https://github.com/dcanje/panel-reportes-giftcard) — agrega un `inyectarPaises` después de `gate` para el `allowedCountries` específico del panel.

## Más información

- [Gate — Servicio de autenticación](https://github.com/dcanje/gate)
- Para registrar tu app en Gate, contacta al administrador.
