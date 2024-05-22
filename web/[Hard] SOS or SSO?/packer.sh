mkdir web_sos_or_sso
cp -r challenge/ build-docker.sh Dockerfile entrypoint.sh web_sos_or_sso
zip -r web_sos_or_sso.zip web_sos_or_sso
rm -r web_sos_or_sso