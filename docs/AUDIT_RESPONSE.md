# Réponse à l'audit du 30 octobre 2026

Audit de référence : commit `a7b6436`, findings F-01 à F-12. Ce document liste, pour chaque
finding, le correctif, le test qui le prouve et l'état. Il ajoute les défauts trouvés en
appliquant les correctifs (F-13 à F-16). Les preuves sont des tests et des sorties d'outils
rejouables, pas des affirmations.

Niveaux de preuve : **Exécuté** (test, fuzzer ou scanner rejouable), **Spec** (extrait de
la spec OpenAPI brute, `docs/evidence/openapi-facts.json`), **Non vérifié** (demande le
tenant ou un vrai client MCP).

## Reproduction de l'audit sur `a7b6436`

| Outil de l'audit | Résultat annoncé | Résultat reproduit |
|---|---|---|
| `test_audit_properties.py` | 12 échecs, 7 réussites | 12 échecs, 7 réussites |
| `mutate_guards.py` | 24/27, survivants : diff size limit, token header format, secret redaction | identique |
| F-05 (`.match` + `\n`) | `_SAFE_VALUE.match('x\n')` vrai | vrai ; aussi `XC_NAME_RE`, `TENANT_RE`, `API_TOKEN_RE` |
| F-12 (proxy) | 0 montage proxy avec transport explicite | 0 contre 1 |

## Findings

| ID | Sév. | État | Correctif | Preuve |
|---|---|---|---|---|
| F-01 | Élevée | Corrigé | `sanitize.text` filtre par catégorie Unicode (Cc, Cf, Co, Cn, Cs) et les sélecteurs de variante | P5, P5b ; `test_F01_*` (bout en bout via MCP) ; invariant atheris |
| F-02 | Élevée | Corrigé | `exclusion_rule_risks` : préfixe `/`, suffixe TLD/suffixe public, joker dans `exact_value`, plus de 5 signatures | P7b (3 cas) ; mutants « F-02 » tués |
| F-03 | Moyenne | Corrigé | `find_references_to` : aucune limite de nombre, sur-approximation (clés supplémentaires acceptées), « incomplet » si profondeur > 64 | P6 ; `test_F03_*` (61 références, 5 clés, spec profonde) |
| F-04 | Moyenne | Ouvert | Mesure dans le client cible (partie E) | Non vérifié |
| F-05 | Faible | Corrigé | `fullmatch` sur les 9 regex de validation ; règle Semgrep `anchored-regex-match` | `test_F05_*` ; invariant atheris strict |
| F-06 | Faible | Corrigé | Comparaison des scalaires sur leur JSON (`true`≠`1`, `1`≠`1.0`, `0.0`≠`-0.0`) | P1, P4 ; `test_F06_*` ; reconstruction exacte |
| F-07 | Faible | Corrigé | 3 tests ajoutés | mutation : les 3 anciens survivants sont tués |
| F-08 | Moyenne | Partiel | `CODEOWNERS` ajouté ; renommage en `main` et protection : action GitHub du propriétaire | — |
| F-09 | Faible | Accepté | Pas de précondition dans l'API publiée : fenêtre GET→PUT documentée ; empreinte spec + métadonnées + uid | Spec : `version_precondition_in_put = []` pour les 6 types modifiables |
| F-10 | Info | Ouvert | `f5xc-waap-mcp check` (déjà livré) | Spec : `whoami` documente `name`, `email`, `user_uuid`, `type` ; comportement réel non vérifié |
| F-11 | Info | Corrigé | `tests/test_read_tools_coverage.py` | couverture de branches : `config_read.py` 71 → 100 %, `security.py` 72 → 98 %, total 87 → 92 % |
| F-12 | Moyenne | Corrigé | `F5XC_MCP_HTTPS_PROXY` (URL validée, sans identifiants) passé au transport | `test_F12_*` |
| F-13 | Moyenne | Corrigé | Nouveau. Une clé de spec terminée par `\n` ajoutait une ligne au diff de confirmation (`_PLAIN_KEY.match`) | `test_F13_*` ; invariant atheris |
| F-14 | Faible | Corrigé | Nouveau. « Objet supprimé » et « objet vidé » s'affichaient pareil ; ligne explicite `(whole object removed)` | propriété de reconstruction exacte (4 000 cas) |
| F-15 | Élevée | Corrigé | Nouveau. `populate_by_name=True` faisait lire les variables par **nom de champ** : `MODE=write` + `ENABLE_WRITES=true` activaient l'écriture, `API_TOKEN` fournissait un token, `https_proxy` le proxy | `test_F15_*` ; règle Semgrep `settings-populate-by-name` ; mutant tué |
| F-17 | Moyenne | Corrigé | Nouveau, en partie introduit par le correctif F-02. Les raisons HIGH RISK inséraient sans échappement le nom de la règle d'exclusion, `suffix_value`, `exact_value` et les chemins de champs des référents (clés venant de XC) : un saut de ligne fabriquait de fausses lignes dans le bandeau. Valeurs échappées en JSON (`shown()`), et chaque raison réduite à une ligne dans `confirmation_message` | `test_F17_*` |
| F-16 | Moyenne | Partiel | Nouveau. Image : 271 vulnérabilités Debian (2 CRITICAL, 59 HIGH) et `pip 25.0.1` (6 CVE). Base trixie (164, 0 CRITICAL, 44 HIGH, toutes sans correctif publié) ; pip retiré de l'image ; Trivy en CI bloquant sur toute HIGH/CRITICAL corrigeable | Trivy 0.76.1 et OSV-Scanner 2.7.0 sur l'image construite |

### Deuxième revue (N1 à N5)

| ID | Sév. | État | Correctif | Preuve |
|---|---|---|---|---|
| N1 | Moyenne | Corrigé | L'interrupteur d'arrêt est revérifié juste avant le PUT (il pouvait être posé pendant la lecture du diff) | `test_N1_*` (l'interrupteur est posé dans le rappel d'élicitation) ; mutant tué |
| N2 | Faible | Corrigé | Échec d'écriture du rollback intercepté : le changement appliqué est renvoyé comme appliqué, `rollback_available: false`, événement `rollback_failed` | `test_N2_*` ; mutant tué |
| N3 | Moyenne | Corrigé | Les secrets ne vont jamais sur disque : marqueur à l'écriture, secret repris de l'objet vivant au revert ; revert refusé si l'emplacement d'un secret a changé ou s'il a disparu | `test_N3_*` (clé privée `clear_secret_info` absente du fichier, secret tourné entre-temps correctement repris) ; mutants tués |
| N4 | Info | Décidé | Revert du changement d'un autre autorisé (besoin d'exploitation ; le RBAC XC reste la frontière), mais auteur et date dans le résumé, et HIGH RISK : le hash est à retaper | `test_N4_*` ; mutant tué |
| N5 | Faible | Corrigé | Public Suffix List embarquée (ICANN + privée, version 2026-10-28, MPL-2.0), `scripts/update_psl.py` pour la rafraîchir | `test_N5_*` (`gouv.fr`, `github.io`, règles `*.ck` / `!www.ck`) ; mutant tué |

Défaut de l'outillage d'audit : la règle Semgrep `model-arg-in-fstring-url` ne déclenchait
pas sur `f"/api/config/namespaces/{name}"`. Son « 0 finding » ne prouvait rien. Motif
corrigé ; chaque règle a maintenant des cas positifs et négatifs testés par
`semgrep --test` (5/5).

## Hypothèses

| Hypothèse | État | Preuve |
|---|---|---|
| En mode read, aucun outil d'écriture n'est exposé | Vérifié | mutant tué ; `test_registry.py` |
| Seules les variables `F5XC_*` configurent le serveur | Vérifié (était infirmé : F-15) | `test_F15_*` |
| Tout chemin XC vient du catalogue fermé | Vérifié | Semgrep `xc-path-not-from-catalog`, testé par cas positif |
| Une valeur de filtre ne peut pas casser la requête de logs | Vérifié (était infirmé : F-05) | P8, `test_F05_*`, atheris |
| Le token n'apparaît jamais dans un log, une erreur ou un résultat | Vérifié (statique) | Semgrep taint, 0 finding, cas positifs détectés |
| Tout changement envoyé à XC apparaît dans le diff, sans ambiguïté | Vérifié (était infirmé : F-06, F-14) | reconstruction exacte, P1, P2 |
| Les lignes du diff et du bandeau ne peuvent pas être forgées | Vérifié (était infirmé : F-13, F-17) | P3, `test_F13_*`, `test_F17_*`, atheris |
| Aucun caractère invisible n'atteint le modèle | Vérifié (était infirmé : F-01) | P5, P5b, `test_F01_*` |
| Une exclusion WAF large déclenche HIGH RISK | Vérifié pour les cas testés | P7b, `test_broad_waf_exclusions_*`, `test_N5_*` (Public Suffix List) |
| Un objet créé n'est référencé par rien, ou c'est signalé | Vérifié dans le namespace (était partiel : F-03) | `test_F03_*` ; référents d'autres types ou namespaces non couverts |
| Champs exacts de `app_firewall_detection_control` | Vérifié | Spec : `exclude_attack_type_contexts`, `exclude_bot_name_contexts`, `exclude_signature_contexts`, `exclude_violation_contexts` |
| Le replace réécrit `labels`, `annotations`, `description`, `disable` | Vérifié (spec) | Spec : `replace_metadata_fields` |
| L'API n'offre aucune précondition de version sur PUT | Vérifié (spec) | Spec : paramètres du PUT = chemin + corps ; aucun `resource_version`/`If-Match`/`etag` dans le PUT et ses schémas |
| `whoami` renvoie le propriétaire d'un token API | Non vérifié | Spec : champs documentés ; comportement réel = `f5xc-waap-mcp check` |
| Le client affiche le diff complet dans l'élicitation | Non vérifié | partie E |
| Un modèle suit une instruction cachée | Non vérifié | partie E (la transmission est désormais bloquée : F-01) |
| Dépendances Python sans CVE connue | Vérifié | pip-audit sur 5 verrous ; exception documentée pour l'outil de CI semgrep (CVE-2026-114603, ReDoS sur en-tête HTTP entrant) |
| Image sans CVE corrigeable HIGH/CRITICAL | Vérifié à date | Trivy `--ignore-unfixed` : 0 ; 44 HIGH sans correctif publié restent |

## Preuves rejouables

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock -r requirements-build.lock
pip install --no-deps --no-build-isolation .
pytest                                                    # 231 tests, dont propriétés Hypothesis
python -I scripts/mutate_guards.py . mutation.json        # les 48 garde-fous doivent être tués (exit 1 sinon)
pip install --require-hashes -r requirements-fuzz.lock
python -I fuzz/fuzz_parsers.py -max_total_time=1800       # c32b709 : 166,7 M exécutions, 0 crash
python -m venv /tmp/sast && /tmp/sast/bin/pip install --require-hashes -r requirements-sast.lock
/tmp/sast/bin/semgrep --test --config .semgrep/rules.yml .semgrep/rules.py
/tmp/sast/bin/semgrep scan --metrics=off --error --config .semgrep/rules.yml src
python scripts/openapi_facts.py > docs/evidence/openapi-facts.json   # faits OpenAPI bruts
```

## Reste à faire sur le tenant

Le harnais de l'audit (parties A, C, E, G) reste valable, avec ces outils en plus :

- **C** : `f5xc-waap-mcp check` avec chaque token. Derrière un proxy imposé, définir
  `F5XC_MCP_HTTPS_PROXY` (le serveur ne lit plus `HTTPS_PROXY`, cf. F-15).
- **G, interrupteur d'arrêt** : créer le fichier `F5XC_MCP_WRITE_KILL_SWITCH`. Les écritures
  sont refusées immédiatement, sans redémarrage. Chronométrer aussi la révocation des tokens.
- **G, retour arrière** : avec `F5XC_MCP_ROLLBACK_DIR`, chaque replace appliqué garde l'état
  « avant » (fichier `0600`) ; `plan_revert(plan_id)` produit un plan inverse revu comme un
  autre. Les créations se défont à la main (pas d'outil de suppression).
- **G, corrélation** : `plan_applied` porte `user`, `method`, `path` et `ts`, à apparier avec
  l'audit log XC.
