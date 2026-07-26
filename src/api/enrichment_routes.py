"""Search and enrichment API routes."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.search.local_search import search_local_intelligence
from src.services.ip_enrichment import enrich_ip, search_shodan_live

router = APIRouter(prefix="/api/v1", tags=["search-enrichment"])


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1)
    limit: int = Field(default=50, ge=1, le=200)
    shodan_live: bool = False


class EnrichRequest(BaseModel):
    use_shodan: bool = True
    use_censys: bool = False


@router.post("/search")
def search_intelligence(request: SearchRequest, db: Session = Depends(get_db)):
    """Search local intelligence using Shodan-style query syntax."""
    local_results = search_local_intelligence(db, request.query, limit=request.limit)
    response = {
        "query": request.query,
        "local_results": local_results,
        "local_count": len(local_results),
        "shodan_live": None,
    }

    if request.shodan_live:
        try:
            response["shodan_live"] = search_shodan_live(
                request.query,
                limit=min(request.limit, 10),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    return response


@router.post("/enrich/ip/{ip}")
def enrich_ip_address(
    ip: str,
    request: EnrichRequest,
    db: Session = Depends(get_db),
):
    """Enrich a single IP via Shodan (1 host lookup credit)."""
    try:
        return enrich_ip(
            db,
            ip,
            use_shodan=request.use_shodan,
            use_censys=request.use_censys,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
