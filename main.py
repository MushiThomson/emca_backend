import os
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from models import ContactMessage, Project, Admin, SessionLocal
from starlette.requests import Request

# ✅ Load environment variables
from dotenv import load_dotenv
load_dotenv()

# ✅ Load SECRET_KEY from .env
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "FastAPI on cPanel is working!"}


# ✅ Ensure `uploads` directory exists
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ✅ Serve uploaded files
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ✅ Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ✅ Authentication Helpers
def authenticate_admin(username: str, password: str, db: Session):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not pwd_context.verify(password, admin.password_hash):
        return None
    return admin

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ✅ Secure Admin Authentication
def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        admin = db.query(Admin).filter(Admin.username == username).first()
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return admin
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

# ✅ Contact Form Pydantic Model
class ContactForm(BaseModel):
    name: str
    email: str
    message: str

# ✅ Contact Form API
@app.post("/contact/")
def save_message(contact: ContactForm, db: Session = Depends(get_db)):
    new_message = ContactMessage(
        name=contact.name, 
        email=contact.email, 
        message=contact.message,
        timestamp=datetime.utcnow()
    )
    db.add(new_message)
    db.commit()
    return {"message": "Message received"}

# ✅ Securely Retrieve Contact Messages (Admins Only)
@app.get("/contact/")
def get_messages(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    messages = db.query(ContactMessage).all()
    return [
        {
            "id": msg.id,
            "name": msg.name,
            "email": msg.email,
            "message": msg.message,
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
        for msg in messages
    ]

# ✅ Admin Registration (Only Run Once)
@app.post("/register-admin/")
def register_admin(admin_data: AdminCreate, db: Session = Depends(get_db)):
    if db.query(Admin).filter(Admin.username == admin_data.username).first():
        raise HTTPException(status_code=400, detail="Admin already exists")

    hashed_password = pwd_context.hash(admin_data.password)
    new_admin = Admin(username=admin_data.username, password_hash=hashed_password)
    db.add(new_admin)
    db.commit()
    return {"message": "Admin created successfully"}

# ✅ Login
@app.post("/token/")
def login_admin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = authenticate_admin(form_data.username, form_data.password, db)
    if not admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token({"sub": admin.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# ✅ Project Model
class ProjectSchema(BaseModel):
    title: str
    description: str
    image_url: str

@app.post("/projects/")
async def create_project(
    title: str = Form(...),
    description: str = Form(...),
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    request: Request = None
):
    # Validate image
    allowed_types = {"image/png", "image/jpeg", "image/jpg"}
    if image.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Invalid image format")

    # Save file
    file_location = f"{UPLOAD_DIR}/{image.filename}"
    with open(file_location, "wb") as buffer:
        buffer.write(await image.read())

    # Create dynamic URL
    base_url = str(request.base_url).strip("/")
    image_url = f"{base_url}/uploads/{image.filename}"

    # Save to database
    new_project = Project(title=title, description=description, image_url=image_url)
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    return new_project

# ✅ Get All Projects
@app.get("/projects/")
def get_projects(db: Session = Depends(get_db)):
    return db.query(Project).all()

# ✅ Get a Single Project
@app.get("/projects/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

# ✅ Update a Project (Admins Only)
@app.put("/projects/{project_id}")
def update_project(project_id: int, project: ProjectSchema, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="Project not found")

    db_project.title = project.title
    db_project.description = project.description
    db_project.image_url = project.image_url
    db.commit()
    db.refresh(db_project)
    return db_project

# ✅ Delete a Project (Admins Only)
@app.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="Project not found")

    db.delete(db_project)
    db.commit()
    return {"message": "Project deleted successfully"}
