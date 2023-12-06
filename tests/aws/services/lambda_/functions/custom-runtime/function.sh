function handler () {
    echo "Custom Runtime Lambda handler executing." 1>&2;
    EVENT_DATA=$1
    echo "$EVENT_DATA" 1>&2;
    RESPONSE="Echoing request: '$EVENT_DATA'"

    echo $RESPONSE
}
