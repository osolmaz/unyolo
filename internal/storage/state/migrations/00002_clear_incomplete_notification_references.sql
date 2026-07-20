-- +goose Up
UPDATE grants
SET notification_json = NULL
WHERE notification_json IS NOT NULL
  AND json_extract(notification_json, '$.kind') = 'telegram'
  AND (
    COALESCE(json_extract(notification_json, '$.chat_id'), 0) = 0
    OR COALESCE(json_extract(notification_json, '$.message_id'), 0) <= 0
    OR COALESCE(json_extract(notification_json, '$.renderer'), '') = ''
    OR COALESCE(json_extract(notification_json, '$.text'), '') = ''
    OR COALESCE(json_extract(notification_json, '$.presentation_json'), '') = ''
    OR COALESCE(json_extract(notification_json, '$.presentation_digest'), '') = ''
    OR COALESCE(json_extract(notification_json, '$.rendered_digest'), '') = ''
  );

-- +goose Down
SELECT 1;
