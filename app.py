import hashlib
import csv
import os
import os
from flask import send_file
from flask import Flask, request, render_template, redirect, url_for, jsonify
from dotenv import load_dotenv
from db import create_table, insert_multiple_hashes, is_compromised, get_db_connection

load_dotenv()

database_uri = os.getenv('DATABASE_URI', 'D:/Proyectos/HashMail/hashmail.db')
secret_key = os.getenv('SECRET_KEY', 'defaultkey')

print(f"Database URI: {database_uri}")
print(f"Secret Key: {secret_key}")
print(f"Database URI from .env: {database_uri}")

app = Flask(__name__)

def hash_email(email):
    return hashlib.sha3_256(email.encode()).hexdigest()

@app.route('/')
def index():
    """Mostrar el formulario para agregar correos comprometidos"""
    return render_template('index.html')

@app.route('/add_emails', methods=['POST'])
def add_emails():
    """Agregar correos comprometidos desde el formulario"""
    emails = request.form.get('emails').splitlines()
    if not emails:
        return jsonify({"error": "No emails provided"}), 400
    
    email_hashes = [hash_email(email) for email in emails]
    
    insert_multiple_hashes(email_hashes, emails)
    
    return redirect(url_for('index'))

@app.route('/check', methods=['GET'])
def check_email():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    email_hash = hash_email(email)
    if is_compromised(email_hash):
        return jsonify({"email": email, "compromised": True})
    return jsonify({"email": email, "compromised": False})

@app.route('/add_multiple', methods=['POST'])
def add_multiple_emails():
    data = request.json
    emails = data.get('emails')
    if not emails or not isinstance(emails, list):
        return jsonify({"error": "A list of emails is required"}), 400
    
    email_hashes = [hash_email(email) for email in emails]
    insert_multiple_hashes(email_hashes)
    return jsonify({"emails": emails, "added": True})

@app.route('/remove', methods=['POST'])
def remove_email_by_email():
    """Eliminar un correo electrónico comprometido por su dirección"""
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "No email provided"}), 400

    email_hash = hash_email(email)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM compromised_hashes WHERE email_hash = ?", (email_hash,))
    conn.commit()
    conn.close()

    return redirect(url_for('list_compromised'))

@app.route('/remove/<int:id>', methods=['POST'])
def remove_email_by_id(id):
    """Eliminar un correo electrónico comprometido por su id"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM compromised_hashes WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect(url_for('list_compromised'))

@app.route('/compromised')
def list_compromised():
    """Mostrar los correos comprometidos almacenados en la base de datos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, email_hash FROM compromised_hashes")
    compromised_hashes = cursor.fetchall()
    conn.close()

    return render_template('compromised.html', compromised_hashes=compromised_hashes)

@app.route('/download_csv')
def download_csv():
    """Generar y descargar el archivo CSV con los correos comprometidos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, email_hash FROM compromised_hashes")
    compromised_hashes = cursor.fetchall()
    conn.close()

    filename = 'compromised_emails.csv'
    filepath = os.path.join('downloads', filename)

    if not os.path.exists('downloads'):
        os.makedirs('downloads')

    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Id", "Correo", "Hash"])  
        writer.writerows(compromised_hashes)

    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/delete_database', methods=['POST'])
def delete_database():
    if os.path.exists(database_uri):
        os.remove(database_uri)
        return jsonify({"message": "Base de datos eliminada."}), 200
    else:
        return jsonify({"error": "La base de datos no existe."}), 400

if __name__ == '__main__':
    create_table()
    app.run(host='0.0.0.0', port=5000, debug=True)