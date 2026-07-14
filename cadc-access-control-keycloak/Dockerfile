FROM quay.io/keycloak/keycloak:26.6.4

COPY --chown=keycloak:keycloak build/libs/cadc-access-control-keycloak-*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
