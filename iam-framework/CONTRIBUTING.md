# Contributing to IAM Framework

## Adding a new role tier

1. Add an entry to `src/policies/templates.py` in the `ROLE_TEMPLATES` dict
2. Each action group needs: `sid`, `actions`, optional `require_mfa`, `require_tenant_tag`, `restrict_regions`
3. Write tests in `tests/test_evaluator.py` for at least 3 allow and 3 deny scenarios
4. Run `python src/policies/generator.py --tenant test --role <your_role> --output out/` to verify generation
5. Update README role tier table and CHANGELOG

## Running tests

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -v
```

## Commit style

```
feat(policies): add data-engineer role with Glue and Athena access
fix(evaluator): StringLike operator was not handling ? wildcard correctly
test(evaluator): add SCP blocking scenarios for all role tiers
docs: update Athena query examples in policy_design.md
```
