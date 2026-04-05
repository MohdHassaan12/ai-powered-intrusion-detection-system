from app import app, db, User
from werkzeug.security import generate_password_hash
import getpass

def create_admin():
    with app.app_context():
        # Ensure tables exist
        db.create_all()
        
        print("--- IDS Admin Setup ---")
        username = input("Enter admin username (e.g., email): ")
        
        if User.query.filter_by(username=username).first():
            print(f"[-] User {username} already exists!")
            return
            
        password = getpass.getpass("Enter secure password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("[-] Passwords do not match.")
            return
            
        hashed_pw = generate_password_hash(password, method='scrypt')
        new_admin = User(username=username, password_hash=hashed_pw)
        
        db.session.add(new_admin)
        db.session.commit()
        print(f"[+] Admin account '{username}' successfully created!")

if __name__ == '__main__':
    create_admin()
