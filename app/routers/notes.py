"""
CRUD de "notes", utilisé comme ressource protégée type pour démontrer :
- l'authentification obligatoire (get_current_user) ;
- le contrôle d'accès par propriétaire (chaque utilisateur ne voit et ne
  modifie que ses propres notes — protection contre l'IDOR, OWASP A01) ;
- des requêtes 100% paramétrées via l'ORM (protection contre l'injection
  SQL, OWASP A03 — voir tests/test_injection_attacks.py).
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
    # Même erreur (404) qu'une note trouvée mais appartenant à quelqu'un
    # d'autre : on ne révèle jamais l'existence d'une ressource qui n'est
    # pas à l'utilisateur courant.
    if note is None or note.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note introuvable.")
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
