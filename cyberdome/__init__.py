'''

Code shared by the decision engines and the Web UI:

- data_paths: where the data and config files live
- trust_signals: collects Keycloak login events and reads the latest records per user
- trust_algorithm: calculates a user's trust score
- policy: the Policy Engine's rules, which turn a trust score into allow or deny

'''
