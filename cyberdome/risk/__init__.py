'''

The adaptive risk model (Task 2): how risky an access request is, given everything
the session did so far.

- defaults:  the default settings, and how policyConfiguration.yml (riskModel) overrides them
- features:  the 9 risk features, each scored between 0 (normal) and 1 (very unusual)
- model:     combines the features into a risk score with memory, and picks the risk level
- signals:   counts failed logins and denied requests from the files in data/
- state:     keeps each session's risk and each user's usual behaviour in data/

features, model and defaults read no files, so the tests and the experiments can call
them directly with made-up data.

The model and the reasons behind it are explained in docs/risk-model.md.

'''
