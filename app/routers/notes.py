"""CRUD for "notes", used as a sample protected resource to demonstrate:
- mandatory authentication (get_current_user);
- owner-based access control (IDOR protection, OWASP A01);
- fully parameterized queries via the ORM (SQL injection protection,
  OWASP A03 — see tests/test_injection_attacks.py).
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.database import get_db
from app.models import Note, User
from app.schemas import NoteCreate, NoteOut

router = APIRouter(prefix="/notes", tags=["notes"])


def _get_owned_note_or_404(note_id: int, user: User, db: Session) -> Note:
    note = db.query(Note).filter(Note.id == note_id).first()
    # Same 404 whether the note doesn't exist or belongs to someone else —
    # never reveal that a resource exists if it's not the user's.
    if note is None or note.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return note


@router.get("", response_model=list[NoteOut])
def list_notes(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Note).filter(Note.owner_id == user.id).all()


@router.post("", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_note(
        payload: NoteCreate,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
):
    note = Note(title=payload.title, content=payload.content, owner_id=user.id)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{note_id}", response_model=NoteOut)
def get_note(
        note_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
):
    return _get_owned_note_or_404(note_id, user, db)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
        note_id: int,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
):
    note = _get_owned_note_or_404(note_id, user, db)
    db.delete(note)
    db.commit()
    return None
