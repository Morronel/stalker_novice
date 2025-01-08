# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import sqlite3
import os
import secrets
import base64
import hashlib
from flask_babel import Babel, gettext as _

# Get database path from environment variable or use default
DATABASE_PATH = os.getenv('SQLITE_DATABASE', 'stalker.db')

# Initialize session with default language if not set
def init_session():
    if 'lang' not in session:
        session['lang'] = 'uk'  # Default to Ukrainian
    if 'completed_flags' not in session:
        session['completed_flags'] = {}
    if 'submitted_flags' not in session:
        session['submitted_flags'] = {}
    if 'role' not in session:
        session['role'] = 'stalker'
    session.modified = True  # Ensure session is saved

# Authentication decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'stalker_name' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# Configuration
CHALLENGES = {
    'shed': {
        'flag': 'STALKER{h1dd3n_d1r3ct0ry_m4st3r}',
        'reward': 'Detector'
    },
    'farmhouse': {
        'flag': 'STALKER{sql_1nj3ct10n_n00b}',
        'reward': 'Medkit'
    },
    'dogs': {
        'flag': 'STALKER{x55_4l3rt_m4st3r}',
        'reward': 'Bandages'
    },
    'abandoned': {
        'flag': 'STALKER{brut3_f0rc3_m4st3r}',
        'reward': 'Antirad'
    },
    'technician': {
        'flag': 'STALKER{crypt0_m4st3r}',
        'reward': 'Toolkit'
    },
    'anomaly': {
        'flag': 'STALKER{tr4ff1c_sn1ff3r}',
        'reward': 'Protection suit'
    },
    'bandit': {
        'flag': 'STALKER{c00k1e_m0nst3r}',
        'reward': 'Weapon'
    },
    'garage': {
        'flag': 'STALKER{h34d3r_1nsp3ct0r}',
        'reward': 'Night vision goggles'
    },
    'vending': {
        'flag': 'STALKER{p0st_m4st3r}',
        'reward': 'Energy drink'
    }
}

TECHNICIAN_CHALLENGES = {
    'base64': {
        'encoded': 'U3RhbGtlcnMgYXJlIHRoZSBiZXN0IQ==',  # "Stalkers are the best!"
        'completed': False
    },
    'xor': {
        'ciphertext': 'Kzs+FDY6LzkqJDgiPDoTIiALOy4yPw==',  # Base64(XOR("xor_encryption_is_weak", "STLK"))
        'key': 'STLK',
        'completed': False
    },
    'md5': {
        'hash': '5f4dcc3b5aa765d61d8327deb882cf99',  # MD5 of "password"
        'completed': False
    }
}

# Список дозволених сторінок
ALLOWED_PAGES = [
    'campfire', 'sydorovich', 'commonpaths', 'commonusernames', 'commonpasswords'
] + list(CHALLENGES.keys())

def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    # Drop the table if it exists
    c.execute('DROP TABLE IF EXISTS treasures')
    # Create the table
    c.execute('''CREATE TABLE IF NOT EXISTS treasures
                 (id INTEGER PRIMARY KEY, location TEXT, coordinates TEXT, flag TEXT)''')
    # Insert the correct flag
    c.execute('INSERT INTO treasures (id, location, coordinates, flag) VALUES (1, "Ферма", "45.7845, 30.4521", ?)',
              (CHALLENGES['farmhouse']['flag'],))
    conn.commit()
    conn.close()

def get_locale():
    # First try to get the language from the session
    if 'lang' in session:
        return session['lang']
    # Then try to get it from the browser's accept languages
    return request.accept_languages.best_match(['en', 'uk'])

def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)
    
    # Configure Babel with the modern API
    babel = Babel()
    babel.init_app(app, locale_selector=lambda: get_locale())
    init_db()
    return app

app = create_app()

# Make get_locale available in templates
@app.context_processor
def utility_processor():
    return dict(get_locale=get_locale)

@app.before_request
def before_request():
    init_session()

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in ['en', 'uk']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

def init_session_flags():
    if 'completed_flags' not in session:
        session['completed_flags'] = {}
    if 'submitted_flags' not in session:
        session['submitted_flags'] = {}

def save_flag(location, flag):
    """Helper function to consistently save flags"""
    if location in CHALLENGES and CHALLENGES[location]['flag'] == flag:
        # Always save to both places for consistency
        session['completed_flags'][location] = flag
        session['submitted_flags'][location] = flag
        session.modified = True
        return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/map', methods=['GET', 'POST'])
def map():
    if request.method == 'POST':
        stalker_name = request.form.get('stalker_name')
        if stalker_name:
            session['stalker_name'] = stalker_name
            init_session_flags()
            return render_template('map.html')
    elif 'stalker_name' in session:
        return render_template('map.html')
    return redirect(url_for('index'))

@app.route('/location/<name>')
@requires_auth
def location(name):
    if name not in ALLOWED_PAGES:
        return redirect(url_for('map'))
    init_session_flags()
    return render_template(f'locations/{name}.html')

# Новий роут для брутфорсу директорій в сараї
@app.route('/location/shed/<path>')
@requires_auth
def shed_path(path):
    if path == 'console':  # Змініть на будь-який інший шлях з commonpaths.html
        return render_template('locations/console.html')
    return jsonify({
        'success': False,
        'message': _('Error: Invalid path')
    }), 404

@app.route('/api/check_flag', methods=['GET', 'POST'])
@requires_auth
def check_flag():
    init_session_flags()
    
    # Handle GET requests for the anomaly challenge
    if request.method == 'GET':
        signal = request.args.get('signal')
        flag = request.args.get('flag')
        
        if signal == 'test' and flag == CHALLENGES['anomaly']['flag']:
            save_flag('anomaly', flag)  # Use helper function
            return jsonify({
                'success': True,
                'message': _('Signal received successfully.'),
                'reward': _(CHALLENGES['anomaly']['reward'])  # Add reward info
            })
        return jsonify({
            'success': True,
            'message': _('Signal processed.')
        })
    
    # Handle POST requests for other challenges
    data = request.get_json()
    location = data.get('location')
    flag = data.get('flag')
    
    if save_flag(location, flag):  # Use helper function
        return jsonify({
            'success': True, 
            'message': _('Correct flag! Here\'s your reward, stalker.'),
            'reward': _(CHALLENGES[location]['reward'])
        })
    return jsonify({
        'success': False,
        'message': _('Incorrect flag. Try again.')
    })

@app.route('/api/get_completed_flags')
@requires_auth
def get_completed_flags():
    init_session_flags()
    completed = {}
    for location, flag in session.get('completed_flags', {}).items():
        completed[location] = {
            'flag': flag,
            'reward': _(CHALLENGES[location]['reward'])
        }
    return jsonify(completed)

@app.route('/api/submit_sql', methods=['POST'])
@requires_auth
def submit_sql():
    query = request.get_json().get('query', '').lower()
    
    # Basic SQL injection prevention
    if any(x in query for x in ['update', 'delete', 'drop', 'insert', ';', '--']):
        return jsonify({
            'success': False,
            'message': _('Error: Forbidden SQL operations')
        })
    
    # Check if the query is a SELECT statement
    if not query.startswith('select'):
        return jsonify({
            'success': False,
            'message': _('Error: Only SELECT queries are allowed')
        })
    
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    
    try:
        cursor = conn.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        if not result:
            return jsonify({
                'success': True,
                'data': _('Query executed successfully, but no results found')
            })
        
        # Convert row objects to dictionaries
        formatted_results = []
        for row in result:
            row_dict = dict(row)
            # Check if this row contains the flag
            if 'flag' in row_dict and row_dict['flag'] == CHALLENGES['farmhouse']['flag']:
                # User found the flag, but don't save it
                # If only flag was selected, return just the flag
                if len(row_dict) == 1 and 'flag' in row_dict:
                    return jsonify({
                        'success': True,
                        'data': [{'flag': row_dict['flag']}]
                    })
                # Otherwise return all columns
                return jsonify({
                    'success': True,
                    'flag': row_dict['flag'],
                    'id': row_dict['id'],
                    'location': row_dict['location'],
                    'coordinates': row_dict['coordinates']
                })
            formatted_results.append(row_dict)
        
        return jsonify({
            'success': True,
            'data': formatted_results
        })
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            'success': False,
            'message': f'SQL Error: {str(e)}'
        })

# Новий роут для сейфу в покинутому будинку
@app.route('/location/abandoned/safe', methods=['POST'])
@requires_auth
def check_safe():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username:
        return jsonify({
            'success': False,
            'message': _('Enter login!')
        })
    
    if username != 'stalker':
        return jsonify({
            'success': False,
            'message': _('Invalid credentials')
        })
    
    if not password:
        return jsonify({
            'success': False,
            'message': _('Enter password!')
        })
    
    if password != 'zone':
        return jsonify({
            'success': False,
            'message': _('Incorrect password')
        })
    
    # If we got here, both username and password are correct
    return jsonify({
        'success': True,
        'message': _('Safe opened! You found a flag: ') + CHALLENGES["abandoned"]["flag"],
        'flag': CHALLENGES["abandoned"]["flag"]
    })

@app.route('/api/technician/base64', methods=['POST'])
@requires_auth
def check_base64():
    data = request.get_json()
    decoded = data.get('decoded', '').strip()
    
    try:
        correct = base64.b64decode(TECHNICIAN_CHALLENGES['base64']['encoded']).decode('utf-8')
        if decoded == correct:
            session['technician_base64'] = True
            session.modified = True
            return jsonify({
                'success': True,
                'message': _('*Monitor flashes green* Ha! You cracked this message like a can of tushonka!')
            })
    except:
        pass
    
    return jsonify({
        'success': False,
        'message': _('*Monitor flashes red* Something\'s wrong... Maybe try a different decoder?')
    })

@app.route('/api/technician/xor', methods=['POST'])
@requires_auth
def check_xor():
    data = request.get_json()
    decrypted = data.get('decrypted', '').strip()
    
    try:
        # First decode base64
        ciphertext_bytes = base64.b64decode(TECHNICIAN_CHALLENGES['xor']['ciphertext'])
        key_bytes = TECHNICIAN_CHALLENGES['xor']['key'].encode()
        
        # XOR operation
        decrypted_bytes = b''
        for i in range(len(ciphertext_bytes)):
            decrypted_bytes += bytes([ciphertext_bytes[i] ^ key_bytes[i % len(key_bytes)]])
        
        if decrypted == decrypted_bytes.decode():
            session['technician_xor'] = True
            session.modified = True
            return jsonify({
                'success': True,
                'message': _('*Screen sparks* Ha! Well done! The encryption didn\'t stop you!')
            })
    except:
        pass
    
    return jsonify({
        'success': False,
        'message': _('*System shows error* Hmm... Maybe decode base64 first, then XOR? By the way, heard about CyberChef? They say it\'s a useful tool...')
    })

@app.route('/api/technician/md5', methods=['POST'])
@requires_auth
def check_md5():
    data = request.get_json()
    word = data.get('word', '').strip()
    
    if hashlib.md5(word.encode()).hexdigest() == TECHNICIAN_CHALLENGES['md5']['hash']:
        session['technician_md5'] = True
        session.modified = True
        return jsonify({
            'success': True,
            'message': _('*PDA beeps with satisfaction* Bingo! The bandits clearly didn\'t expect someone to guess their password!')
        })
    
    return jsonify({
        'success': False,
        'message': _('*PDA hums disapprovingly* Not that... Maybe it\'s a simple word? Bandits usually don\'t get fancy. Try md5 hash lookup.')
    })

@app.route('/api/technician/check_completion', methods=['GET'])
@requires_auth
def check_technician_completion():
    if all([
        session.get('technician_base64'),
        session.get('technician_xor'),
        session.get('technician_md5')
    ]):
        return jsonify({
            'success': True,
            'flag': CHALLENGES['technician']['flag'],
            'message': _('*Technician nods approvingly* Here\'s your reward, stalker!')
        })
    return jsonify({
        'success': False,
        'message': _('*Technician shakes his head* Nah, finish all the challenges first, stalker.')
    })

@app.route('/api/anomaly/signal', methods=['GET'])
@requires_auth
def anomaly_signal():
    response = jsonify({
        'success': True,
        'message': _('Signal sent successfully. Check the network traffic for hidden data...')
    })
    response.headers['X-Flag'] = CHALLENGES['anomaly']['flag']
    return response

@app.route('/location/garage')
@requires_auth
def garage():
    return render_template('locations/garage.html')

@app.route('/api/garage/check')
@requires_auth
def check_garage():
    response = jsonify({
        'success': True,
        'message': _('Car inspection complete. Nothing unusual in plain sight...')
    })
    response.headers['X-Secret-Flag'] = CHALLENGES['garage']['flag']
    return response

@app.route('/api/vending/buy', methods=['POST'])
@requires_auth
def buy_flag():
    data = request.get_json()
    quantity = data.get('quantity', 0)
    price = data.get('price', 1000000)
    
    if quantity <= 0:
        return jsonify({
            'success': False,
            'message': _('Invalid quantity')
        })
    
    total_cost = quantity * price
    if price != 1:
        return jsonify({
            'success': False,
            'message': _('Not enough coupons! You need 1 000 000 coupons to buy a flag.')
        })
    
    # If price was modified to 1, give the flag but don't save it
    return jsonify({
        'success': True,
        'message': _('*Machine whirs* Here\'s your flag!'),
        'flag': CHALLENGES['vending']['flag']
    })

@app.route('/api/submit_flag', methods=['POST'])
@requires_auth
def submit_flag():
    init_session_flags()
    data = request.get_json()
    location = data.get('location')
    flag = data.get('flag')
    
    if save_flag(location, flag):  # Use helper function
        return jsonify({
            'success': True, 
            'message': _('Correct flag! Here\'s your reward, stalker.'),
            'reward': _(CHALLENGES[location]['reward'])
        })
    return jsonify({
        'success': False,
        'message': _('Incorrect flag. Try again.')
    })

@app.route('/api/get_submitted_flags')
@requires_auth
def get_submitted_flags():
    init_session_flags()
    completed = {}
    for location, flag in session.get('submitted_flags', {}).items():
        completed[location] = {
            'flag': flag,
            'reward': _(CHALLENGES[location]['reward'])
        }
    return jsonify(completed)

@app.route('/api/set_role', methods=['POST'])
@requires_auth
def set_role():
    data = request.get_json()
    role = data.get('role')
    
    if role == 'bandit':
        session['role'] = 'bandit'
        save_flag('bandit', CHALLENGES['bandit']['flag'])  # Use helper function
        return jsonify({
            'success': True,
            'message': _('Role changed successfully'),
            'flag': CHALLENGES['bandit']['flag']
        })
    
    return jsonify({
        'success': False,
        'message': _('Invalid role')
    })

@app.route('/api/debug_session')
@requires_auth
def debug_session():
    return jsonify({
        'completed_flags': session.get('completed_flags', {}),
        'submitted_flags': session.get('submitted_flags', {}),
        'total_flags': len(CHALLENGES)
    })

@app.route('/api/submit_flags_bulk', methods=['POST'])
@requires_auth
def submit_flags_bulk():
    init_session_flags()
    data = request.get_json()
    flags = data.get('flags', {})
    
    results = {}
    for location, flag in flags.items():
        if save_flag(location, flag):
            results[location] = {
                'success': True,
                'message': _('Correct flag! Here\'s your reward, stalker.'),
                'reward': _(CHALLENGES[location]['reward'])
            }
        else:
            results[location] = {
                'success': False,
                'message': _('Incorrect flag. Try again.')
            }
    
    return jsonify({
        'results': results,
        'total_submitted': len(session.get('submitted_flags', {}))
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
