#!/bin/sh
# Restart the iLO using the web server REST endpoint.
# This does not reboot the main system.
if [ $# -ne 3 ] ; then
    echo "Usage: $0 URL USERNAME PASSWORD"
    echo "Example: $0 https://my-ilo.example.org admin pwd12345"
    exit
fi
BASEURL="$1"
USERNAME="$2"
PASSWORD="$3"

# Login using the /json endpoint
LOGIN_OUTPUT="$(curl -ki "$BASEURL/json/login_session" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data '{"method":"login","user_login":"'"$USERNAME"'","password":"'"$PASSWORD"'"}')"
if [ $? != 0 ] ; then
    echo >&2 "Login failed:"
    echo >&2 "$LOGIN_OUTPUT"
    exit 1
fi

SESSION_KEY="$(echo "$LOGIN_OUTPUT" | sed -n 's/^Set-Cookie: *sessionKey=\([^ ;]*\) *;.*/\1/pi')"
if [ -z "$SESSION_KEY" ] ; then
    echo >&2 "Unable to find session key cookie in curl output:"
    echo >&2 "$LOGIN_OUTPUT"
    exit 1
fi
echo "session key: $SESSION_KEY"

# Reset the iLO
if curl -ki "$BASEURL/json/ilo_status" \
    -b "sessionKey=$SESSION_KEY" \
    -H 'Content-Type: application/json; charset=utf-8' \
    --data '{"method":"reset_ilo","cause":"config","session_key":"'"$SESSION_KEY"'"}'
then
    echo "iLO reset request was successfully sent"
else
    echo >&2 "Failed to send reset request"
    exit 1
fi

# Sleep a little and try to get the main page
START_TIME="$(date '+%s')"
sleep 10
echo "Trying to connect to iLO again..."
for _ in $(seq 5) ; do
    if curl -k "$BASEURL/json" > /dev/null ; then
        END_TIME="$(date '+%s')"
        echo "iLO is up and running after $((END_TIME-START_TIME)) seconds :)"
        exit 0
    fi
done
echo >&2 "iLO timed out"
exit 1
