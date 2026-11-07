"""Shared latest-row selection for response-scoped history tables."""
from sqlalchemy import select,func


def latest_by(s,model,key,ids,*conditions):
    """Return the newest model row for each key value in ids."""
    if not ids:return {}
    column=getattr(model,key)
    rank=select(model.id,func.row_number().over(
        partition_by=column,order_by=(model.created.desc(),model.id)).label('rank')
    ).where(column.in_(ids),*conditions).subquery()
    rows=s.scalars(select(model).where(model.id.in_(select(rank.c.id).where(rank.c.rank==1))))
    return {getattr(row,key):row for row in rows}
