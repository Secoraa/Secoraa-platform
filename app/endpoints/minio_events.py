import logging
from fastapi import APIRouter, Request, HTTPException

from app.database.session import SessionLocal
from app.services.minio_ingestion import ingest_from_minio

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/minio",
    tags=["MinIO Webhook"],
)


@router.post("/event")
async def handle_minio_event(request: Request):
    """
    Webhook endpoint called by MinIO whenever an object is uploaded.
    """

    try:
        event: dict = await request.json()
    except Exception as e:
        logger.error("Failed to parse event JSON", exc_info=e)
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    records = event.get("Records", [])

    if not records:
        logger.warning("MinIO event received with no Records")
        return {"status": "no_records"}

    processed = 0
    errors = []

    for record in records:
        try:
            bucket_name = record["s3"]["bucket"]["name"]
            object_name = record["s3"]["object"]["key"]

            logger.info(
                "Starting ingestion for bucket=%s object=%s",
                bucket_name,
                object_name,
            )

            # 🔑 CREATE DB SESSION MANUALLY
            db = SessionLocal()
            try:
                ingest_from_minio(bucket_name, object_name, db)
            finally:
                db.close()

            processed += 1

            logger.info(
                "Successfully ingested object=%s from bucket=%s",
                object_name,
                bucket_name,
            )

        except Exception as e:
            logger.exception(
                "Failed to ingest object=%s from bucket=%s",
                object_name,
                bucket_name,
            )
            errors.append(str(e))

    return {
        "status": "processed",
        "processed": processed,
        "errors": errors if errors else None,
    }
