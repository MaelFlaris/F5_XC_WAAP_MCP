# f5xc-waap-mcp

Serveur MCP (Model Context Protocol) pour **F5 Distributed Cloud WAAP**. Il couvre les
load balancers, le WAF, les policies, le bot defense, la sécurité des API, les security
events et les logs. Il est sécurisé par conception :

- **lecture seule par défaut** ;
- les écritures passent par un **plan** (diff calculé côté serveur), puis une
  **confirmation humaine** (MCP elicitation), puis l'**application** ;
- **aucune suppression** et **aucun outil de requête générique**.

Les endpoints viennent de la référence API officielle (`data/catalog.json`, généré par
`scripts/generate_catalog.py` à partir des spécifications OpenAPI publiées sur
docs.cloud.f5.com).

- Liste des fonctionnalités couvertes : [docs/FEATURES.md](docs/FEATURES.md)
- Modèle de menaces : [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Points à valider sur un tenant : [docs/UNCERTAINTIES.md](docs/UNCERTAINTIES.md)

## Outils

**Lecture (toujours disponibles)**

| Outil | Rôle |
|---|---|
| `list_supported_kinds` | Les 40 types d'objets couverts, par famille, avec le lien vers la doc |
| `list_namespaces` | Namespaces autorisés |
| `list_objects(kind, namespace)` | Liste d'un type d'objet (LB, origin pools, WAF, service policies, rate limiters, API definitions, zones DNS...) |
| `get_object(kind, namespace, name, view)` | `summary` (options configurées et références), `spec` (secrets masqués) ou `referrers` (qui utilise l'objet) |
| `get_active_service_policies` | Service policies actives au niveau du namespace |
| `get_lb_security_posture` | Protections actives d'un LB HTTP (WAF et son mode, bot, API discovery, IP reputation, rate limit, DDoS, TLS...) avec des constats classés par sévérité |
| `audit_namespace_security` | La même posture pour tous les LB HTTP d'un namespace |
| `query_security_events` / `aggregate_security_events` | Security events filtrés, top signatures / IP / pays / LB |
| `query_security_incidents`, `query_suspicious_users` | Incidents, utilisateurs suspects |
| `query_access_logs` / `aggregate_access_logs` | Access logs et agrégations (codes de réponse, chemins...) |
| `query_audit_logs` | Qui a modifié quoi dans le namespace |
| `suggest_waf_exclusion_rule` | Règle d'exclusion proposée par XC pour un faux positif |
| `get_lb_dos_mitigation_rules`, `get_lb_dns_info`, `get_waf_signatures_version` | DDoS auto-mitigation, infos DNS du LB, version des signatures |

**Écriture (seulement avec `F5XC_MCP_MODE=write` et `F5XC_MCP_ENABLE_WRITES=true`)**

| Outil | Rôle |
|---|---|
| `plan_set_lb_waf` | Attacher (ou retirer) un App Firewall sur un LB |
| `plan_set_waf_mode` | Passer un WAF en blocking ou en monitoring |
| `plan_update_ip_prefix_set` | Ajouter ou retirer des IP d'une liste (blocage, allowlist) |
| `plan_add_waf_exclusion_rule` | Ajouter une exclusion WAF (faux positif). Les règles qui désactivent tout le WAF sont refusées |
| `plan_replace_object`, `plan_create_object` | Remplacer la spec ou créer un objet d'un type modifiable ; les champs de premier niveau sont vérifiés contre la doc |
| `apply_plan(plan_id)` | Applique un plan après confirmation : l'utilisateur doit retaper le nom de l'objet |

Un plan est à usage unique, lié à l'identité qui l'a créé, et expire après 5 minutes.
Il est refusé si l'objet a changé entre le plan et l'application. Les namespaces
`system` et `shared` ne sont jamais modifiés.

## Installation

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `F5XC_TENANT` | (obligatoire) | Identifiant court du tenant : `https://<tenant>.console.ves.volterra.io` |
| `F5XC_ALLOWED_NAMESPACES` | (obligatoire) | Liste séparée par des virgules ; tout autre namespace est refusé |
| `F5XC_API_TOKEN` | — | stdio uniquement : **ton** token API personnel. Interdit en mode HTTP |
| `F5XC_MCP_MODE` | `read` | `read` ou `write` |
| `F5XC_MCP_ENABLE_WRITES` | `false` | Doit aussi valoir `true` pour activer l'écriture |
| `F5XC_MCP_TRANSPORT` | `stdio` | `stdio` ou `streamable-http` |
| `F5XC_MCP_BIND_HOST` / `_PORT` | `127.0.0.1` / `8765` | Loopback uniquement (mettre un reverse proxy TLS devant) |
| `F5XC_MCP_ALLOWED_HOSTS` / `_ORIGINS` | localhost | Valeurs `Host` et `Origin` acceptées (anti DNS rebinding) |
| `F5XC_MCP_CA_BUNDLE` | — | CA supplémentaire (proxy d'entreprise) ; la vérification TLS ne peut pas être désactivée |
| `F5XC_MCP_RATE_PER_MINUTE` / `_GLOBAL_RATE_PER_MINUTE` | 60 / 300 | Limites de débit |
| `F5XC_MCP_MAX_EVENTS`, `_MAX_ITEMS`, `_MAX_QUERY_WINDOW_H` | 100, 200, 168 | Bornes des réponses |
| `F5XC_MCP_PLAN_TTL_S` | 300 | Durée de vie d'un plan |
| `F5XC_MCP_AUDIT_LOG` | stderr | Fichier du journal d'audit JSON |

### Token et droits

Crée un **token API personnel** dans la console XC (Account > Credentials). Les droits
du serveur sont ceux de ton rôle XC : commence avec un rôle en lecture sur les
namespaces concernés, et ne passe à un rôle d'écriture que pour le mode write.

### Claude Code (stdio)

`.mcp.json`. Le token est lu depuis ton environnement, jamais écrit dans le fichier :

```json
{
  "mcpServers": {
    "f5xc-waap": {
      "command": "f5xc-waap-mcp",
      "env": {
        "F5XC_TENANT": "acme-corp",
        "F5XC_ALLOWED_NAMESPACES": "prod,staging",
        "F5XC_API_TOKEN": "${F5XC_API_TOKEN}"
      }
    }
  }
}
```

### Mode HTTP (multi-utilisateur)

```bash
F5XC_TENANT=acme-corp F5XC_ALLOWED_NAMESPACES=prod F5XC_MCP_TRANSPORT=streamable-http \
F5XC_MCP_ALLOWED_HOSTS=mcp.example.com F5XC_MCP_ALLOWED_ORIGINS=https://mcp.example.com \
f5xc-waap-mcp
```

Chaque client envoie son propre token dans l'en-tête `X-F5XC-API-Token`. Le serveur
n'a pas de token à lui. Termine le TLS sur un reverse proxy devant `127.0.0.1:8765`.

## Mettre à jour le catalogue

```bash
python scripts/generate_catalog.py
```

Le script échoue si un chemin utilisé n'existe plus dans la documentation.

## Licence

MIT, voir [LICENSE](LICENSE).
