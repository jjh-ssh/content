CLOUD_SERVERS_PATH=$(cat $CLOUD_SERVERS_FILE)

if ! [ -z "$XSIAM_CHOSEN_MACHINE_ID" ]
then
  echo "The tests run on XSIAM machine: $XSIAM_CHOSEN_MACHINE_ID"
  UI_URL=`cat $CLOUD_SERVERS_FILE | jq -c ". | .\"$XSIAM_CHOSEN_MACHINE_ID\" | .ui_url"`
  BUCKET_URL="https://console.cloud.google.com/storage/browser/marketplace-v2-dist-dev/upload-flow/builds-xsiam/$XSIAM_CHOSEN_MACHINE_ID/"
  echo "XSIAM machine url: $UI_URL"
  echo "XSIAM machine marketplace bucket: $BUCKET_URL"
fi