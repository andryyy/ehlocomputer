domain=gyst.debinux.de
ip=162.55.49.111
ip2=2.58.53.49
ip3=37.27.93.56
user=andre
token=asfafata3tgeaegsdthdsgtaertfzgh

for object in {1..2}; do
  if [[ "${1}" == "-p" ]]; then
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip} Random ${RANDOM} ${RANDOM} ${RANDOM}" &
  else
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip} Random ${RANDOM} ${RANDOM} ${RANDOM}"
  fi
done

for object2 in {1..2}; do
  if [[ "${1}" == "-p" ]]; then
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip2} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip2} Random ${RANDOM} ${RANDOM} ${RANDOM}" &
  else
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip2} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip2} Random ${RANDOM} ${RANDOM} ${RANDOM}"
  fi
done

for object3 in {1..2}; do
  if [[ "${1}" == "-p" ]]; then
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip3} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip3} Random ${RANDOM} ${RANDOM} ${RANDOM}" &
  else
    curl --insecure "https://${domain}/objects/desks" \
    --resolve ${domain}:443:${ip3} \
    -H "X-ACCESS-TOKEN: ${user}:${token}" \
    --data-raw "name=${ip3} Random ${RANDOM} ${RANDOM} ${RANDOM}"
  fi
done

if [[ "${1}" == "-p" ]]; then
  wait
fi
