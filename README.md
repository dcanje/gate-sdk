# Gate SDK

Middleware Express para integrar autenticación de [Gate](https://github.com/dcanje/gate) en aplicaciones internas de Apprecio/Dcanje.

Gate maneja la autenticación (Google OAuth) y autorización (RBAC). Este SDK valida los tokens JWT que Gate emite y expone `req.user` con la información del usuario autenticado.

## Instalación

```bash
npm install git+https://github.com/dcanje/gate-sdk.git
```

## Uso rapido (3 lineas)

```javascript
const { createGateMiddleware } = require('gate-sdk');

const gate = createGateMiddleware({
  appId: 'cotizador-divisas',
  gateUrl: 'https://gate.tu-empresa.com',
  publicKey: process.env.GATE_PUBLIC_KEY
});

app.use(gate);
```

## Configuracion

| Opcion | Tipo | Default | Descripcion |
|--------|------|---------|-------------|
| `appId` | String | — | **Requerido**. Slug de la app registrada en Gate |
| `gateUrl` | String | — | **Requerido**. URL base del servicio Gate |
| `publicKey` | String | — | **Requerido**. Clave publica RSA de Gate (PEM) |
| `validateWithGate` | Boolean | `true` | Consultar `/auth/validate` de Gate para detectar tokens invalidados (cambios de rol, desactivacion, etc). |
| `cacheTtl` | Number | `60000` | Duracion del cache de validacion en ms (60s). `0` = sin cache (consulta siempre). |
| `failOpenOnNetworkError` | Boolean | `false` | **Seguridad vs disponibilidad.** Default `false`: si Gate no responde, retorna 503 y preserva la garantia de revocacion inmediata. `true`: permite pasar con solo firma JWT valida (defeat tokenVersion). |

## Invalidacion inmediata de tokens

Por defecto, el SDK consulta a Gate para verificar que el token no ha sido invalidado (token versioning). Si un admin cambia roles, permisos o desactiva un usuario en Gate, el token se invalida **inmediatamente** en el panel admin y en **maximo 60s** en las apps consumidoras (configurable con `cacheTtl`).

Si Gate esta caido (error de red/timeout), por default el SDK devuelve **503 Service Unavailable** en vez de dejar pasar silenciosamente. Esto preserva la garantia de revocacion inmediata: un token revocado por tokenVersion NO puede usarse si el middleware no puede verificar contra Gate. Para apps que prioricen disponibilidad sobre revocacion inmediata, agregar `failOpenOnNetworkError: true`.

Si Gate responde 401 explicitamente, el token se rechaza en todos los casos.

Para desactivar esta validacion (no recomendado en produccion):
```javascript
createGateMiddleware({ ..., validateWithGate: false });
```

### Limpiar cache manualmente
```javascript
const { clearValidationCache } = require('gate-sdk');
clearValidationCache();
```

## req.user

Despues del middleware, `req.user` contiene:

```javascript
{
  email: 'usuario@apprecio.com',
  name: 'Nombre Completo',
  picture: 'https://...',
  role: 'vendedor',
  appId: 'cotizador-divisas',
  isRoot: false
}
```

## requireRole

Middleware adicional para restringir por rol:

```javascript
const { requireRole } = require('gate-sdk');

// Solo vendedores y supervisores
app.get('/ventas', requireRole('vendedor', 'supervisor'), handler);

// Root pasa siempre, no necesita listarse
```

## Variables de entorno

```env
GATE_URL=https://dev-gate-xxx.us-central1.run.app
GATE_APP_ID=mi-aplicacion
GATE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\nMIIBI...
```

La public key se obtiene automáticamente de `GET {GATE_URL}/auth/public-key` o se puede configurar manualmente.

## Flujo

```
Usuario accede a tu app sin token
        │
        ▼
gate-sdk detecta que no hay token
        │
        ▼
Redirige a Gate: /login?app=mi-app&callback=https://mi-app.com
        │
        ▼
Gate autentica con Google
        │
        ▼
Gate redirige de vuelta: https://mi-app.com?gate_token=JWT
        │
        ▼
gate-sdk valida JWT con la public key de Gate
        │
        ▼
req.user disponible con email, nombre, rol
        │
        ▼
Requests siguientes: Authorization: Bearer JWT
```

## Más información

- [Gate — Servicio de autenticación](https://github.com/dcanje/gate)
- Para registrar tu app en Gate, contacta al administrador
