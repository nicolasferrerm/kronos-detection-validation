# KRONOS: validación de detecciones

KRONOS es un laboratorio de purple team seguro por defecto para validar detecciones de identidad en escenarios de Active Directory y Microsoft Entra ID. Genera evidencia sintética, construye consultas para SIEM y produce un reporte HTML.

## Capacidades demostradas

- Escenarios mapeados a MITRE ATT&CK: AS-REP roasting, Kerberoasting y consentimiento de aplicaciones en Entra ID.
- Verificadores de solo lectura para Microsoft Sentinel, Splunk y Elasticsearch.
- Verificador simulado y determinista para demostraciones y pruebas automatizadas.
- Configuración validada con Pydantic y reportes con Jinja2.
- Controles que impiden activar acciones de laboratorio solamente por detectar credenciales.

## Inicio rápido

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python kronos.py --verifier mock --no-delay
```

Este comando no contacta un controlador de dominio, Microsoft Graph ni un SIEM. Los reportes generados quedan fuera del control de versiones.

## Uso responsable

Las integraciones de laboratorio requieren dependencias opcionales, la bandera `--live` y una confirmación explícita. Úsalas únicamente en infraestructura propia o con autorización escrita. No se incluyen credenciales, tickets reales, identificadores de tenants ni reportes generados.

Consulta el [README principal](README.md) para arquitectura, pruebas y limitaciones.
