# Boilerplate-Tabulator_Casbin

## Web App Boilerplate - RBAC System
Un boilerplate completo para aplicaciones web con sistema RBAC (Role-Based Access Control) usando Casbin, autenticación JWT con cookies, y capacidades de exportación PDF/Excel con Tabulator.

## Características Principales
- **RBAC Completo**: Sistema de roles y permisos usando Casbin
- **Autenticación JWT**: Con cookies seguras y middleware de autorización
- **Exportación de Datos**: PDF, Excel y CSV usando Tabulator
- **Base de Datos Simulada**: Archivos JSON para desarrollo rápido
- **Interfaz Responsiva**: Bootstrap 5 con componentes modernos
- **Gestión de Usuarios**: CRUD completo con validación de permisos
- **Sistema de Reportes**: Creación y visualización de datos

## Instalación
```bash
npm install
node server.js
```

## Configuración de Casbin
El sistema usa un modelo RBAC de Casbin con la siguiente estructura:
```
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

### Políticas por Defecto
- **Admin**: Acceso completo (users, reports, roles - read/write/delete)
- **Manager**: Lectura de usuarios, gestión de reportes
- **User**: Solo lectura de reportes

## Funcionalidades de Tabulator
- **PDF**: Documentos formateados con orientación landscape
- **Excel**: Archivos .xlsx con nombres de hojas personalizados
- **CSV**: Formato estándar para importación
- Paginación local
- Filtros por columna
- Ordenamiento
- Columnas móviles

## Sistema de Autenticación

### JWT con Cookies
```javascript
// El token se almacena automáticamente en cookies httpOnly
res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
});
```

### Middleware de Autorización
```javascript
// Verificar permisos específicos
app.get('/api/users', 
    authenticateToken, 
    authorize('users', 'read'), 
    handler
);
```

## API Endpoints

### Autenticación
- `POST /api/auth/login` - Iniciar sesión
- `POST /api/auth/logout` - Cerrar sesión
- `GET /api/auth/me` - Información del usuario actual

### Usuarios
- `GET /api/users` - Listar usuarios (requiere permisos)
- `POST /api/users` - Crear usuario (requiere permisos)
- `DELETE /api/users/:id` - Eliminar usuario (requiere permisos)

### Reportes
- `GET /api/reports` - Listar reportes
- `POST /api/reports` - Crear reporte (requiere permisos)

### Roles y Permisos
- `GET /api/roles` - Listar roles (requiere permisos)
- `POST /api/permissions/check` - Verificar permisos

## Personalización
1. Modifica `policy.csv` o usa la API de Casbin
2. Define las políticas en Casbin
3. Conecta una base de datos para suplantar la carpeta data.

## Seguridad
- Contraseñas hasheadas con bcrypt
- Tokens JWT con expiración
- Cookies httpOnly para prevenir XSS
- Validación de permisos en cada endpoint
- CORS configurado
- Sanitización de datos de entrada

## Variables de Entorno
```bash
# .env (crear este archivo)
JWT_SECRET=tu-clave-secreta-muy-segura
NODE_ENV=production
PORT=3000
```