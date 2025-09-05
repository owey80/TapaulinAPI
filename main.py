from io import BytesIO
from flask import Flask, request, jsonify, send_file, url_for
from google.cloud import datastore, storage

import requests
import json
import os

from urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

USERS = "users"
AVATARS = "avatar"
COURSES = "courses"
ENROLLMENTS = "enrollments"

REQUIRED_COURSE_FIELDS = ['subject', 'number', 'title', 'term', 'instructor_id']

# Update the values of the following 3 variables
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
DOMAIN = os.environ.get("DOMAIN")
GCS_BUCKET = os.environ.get("GCS_BUCKET")
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

datastore_client = datastore.Client()
storage_client = storage.Client()
bucket = storage_client.bucket(GCS_BUCKET)

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

ERROR400 = ({"Error": "The request body is invalid"}, 400)
ERROR401 = ({"Error": "Unauthorized"}, 401)
ERROR403 = ({"Error": "You don't have permission on this resource"}, 403)
ERROR404 = ({"Error": "Not found"}, 404)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request, token=None):
    if 'Authorization' in request.headers and token == None:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

def verify_token(token):
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

def validate_fields(content, required_fields):
    missing = [field for field in required_fields if field not in content]
    if missing:
        return ERROR400
    return None

def upload_avatar_to_gcs(file, user_id):
    blob = bucket.blob(f'avatars/{user_id}.png')
    blob.upload_from_file(file, content_type='image/png')
    return url_for('get_user_avatar', user_id=user_id, _external=True)

def get_avatar_blob(user_id):
    return bucket.blob(f'avatars/{user_id}.png')

@app.route('/')
def index():
    return "API is live :)"

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload
        
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    try:
        content = request.get_json()
        username = content["username"]
        password = content["password"]
    except Exception:
        return ERROR400
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code == 401:
        return ERROR401
    
    auth_data = r.json()
    id_token = auth_data.get("id_token")
    if not id_token:
        return ERROR401
    
    try:
        payload = verify_token(id_token)
    except AuthError as e:
        return handle_auth_error(e)
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())

    if not results:
        return ERROR403
    
    return {'token': id_token}, 200

@app.route('/' + USERS, methods=['GET'])
def get_all_users_admin():
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0]['role'] != "admin":
        return ERROR403
    
    query = datastore_client.query(kind=USERS)
    results = list(query.fetch())
    return_list = list()
    for result in results:
        return_list.append({'id': result.key.id,
                            'role': result['role'],
                            'sub': result['sub']})
    return (return_list, 200)

@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    user_key = datastore_client.key(USERS, user_id)
    user = datastore_client.get(key=user_key)
    if user is None:
        return ERROR404
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or (results[0]['role'] != "admin" and results[0].key.id != user_id):
        return ERROR403
    
    user_data = {
        'id': user_id,
        'role': user['role'],
        'sub': user['sub']
    }

    blob = get_avatar_blob(user_id)
    if blob.exists():
        user_data['avatar_url'] = url_for('get_user_avatar', user_id=user_id, _external=True)

    if user['role'] in ['instructor', 'student']:
        courses = []
        query = datastore_client.query(kind=COURSES)
        for c in query.fetch():
            if user['role'] == 'instructor' and c['instructor_id'] == user_id:
                courses.append(url_for('get_course_by_id', course_id=c.key.id, _external=True))
            elif user['role'] == 'student' and 'students' in c and user_id in c['students']:
                courses.append(url_for('get_course_by_id', course_id=c.key.id, _external=True))
        user_data['courses'] = courses

    return user_data, 200

            
@app.route('/' + USERS + '/<int:user_id>' + '/' + AVATARS, methods=['POST'])
def post_user_avatar(user_id):
    if 'file' not in request.files:
        return ERROR400
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.png'):
        return ERROR400
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0].key.id != user_id:
        return ERROR403
    
    avatar_url = upload_avatar_to_gcs(file, user_id)
    return {"avatar_url": avatar_url}, 200

@app.route('/' + USERS + '/<int:user_id>' + '/' + AVATARS, methods=['GET'])
def get_user_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0].key.id != user_id:
        return ERROR403
    
    blob = get_avatar_blob(user_id)
    if not blob or not blob.exists():
        return ERROR404
    
    data = blob.download_as_bytes()
    return send_file(BytesIO(data), mimetype='image/png')

@app.route('/' + USERS + '/<int:user_id>' + '/' + AVATARS, methods=['DELETE'])
def delete_avatar_by_user_id(user_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0].key.id != user_id:
        return ERROR403
    
    blob = get_avatar_blob(user_id)
    if not blob or not blob.exists():
        return ERROR404
    
    blob.delete()
    return ('', 204)

@app.route('/' + COURSES, methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0]['role'] != "admin":
        return ERROR403
    
    content = request.get_json()
    error = validate_fields(content, REQUIRED_COURSE_FIELDS)
    if error:
        return error
    
    user_key = datastore_client.key(USERS, content['instructor_id'])
    user = datastore_client.get(key=user_key)
    if user is None or user['role'] != 'instructor':
        return ERROR400
    
    course_key = datastore_client.key(COURSES)
    new_course = datastore.Entity(key=course_key)
    new_course.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id']
    })
    datastore_client.put(new_course)
    new_course['id'] = new_course.key.id
    new_course['self'] = url_for("get_course_by_id", course_id=new_course['id'], _external=True)
    return new_course, 201

@app.route('/courses', methods=['GET'])
def get_all_courses():
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 3))
    query = datastore_client.query(kind=COURSES)
    query.order = ["subject"]
    results = list(query.fetch(offset=offset, limit=limit))
    courses = []
    for course in results:
        courses.append({
            "id": course.key.id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": url_for("get_course_by_id", course_id=course.key.id, _external=True)
        })
    next_link = None
    if len(results) == limit:
        next_link = url_for("get_all_courses", offset=offset+limit, limit=limit, _external=True)
    output = {"courses": courses}
    if next_link:
        output["next"] = next_link
    return output, 200

@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course_by_id(course_id):
    course_key = datastore_client.key(COURSES, course_id)
    course = datastore_client.get(course_key)
    if not course:
        return ERROR404
    return {
        "id": course.key.id,
        "subject": course["subject"],
        "number": course["number"],
        "title": course["title"],
        "term": course["term"],
        "instructor_id": course["instructor_id"],
        "self": url_for("get_course_by_id", course_id=course.key.id, _external=True)
    }, 200

@app.route('/courses/<int:course_id>', methods=['PATCH'])
def patch_course(course_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401
    
    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0]['role'] != "admin":
        return ERROR403

    course_key = datastore_client.key(COURSES, course_id)
    course = datastore_client.get(course_key)
    if not course:
        return ERROR403

    content = request.get_json()
    if "instructor_id" in content:
        instructor_key = datastore_client.key(USERS, int(content["instructor_id"]))
        instructor = datastore_client.get(instructor_key)
        if not instructor or instructor.get("role") != "instructor":
            return ERROR400

    course.update(content)
    datastore_client.put(course)
    return {
        "id": course_id,
        "subject": course["subject"],
        "number": int(course["number"]),
        "title": course["title"],
        "term": course["term"],
        "instructor_id": int(course["instructor_id"]),
        "self": url_for("get_course_by_id", course_id=course_id, _external=True)
    }, 200

@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401

    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results or results[0]['role'] != "admin":
        return ERROR403

    course_key = datastore_client.key(COURSES, course_id)
    course = datastore_client.get(course_key)
    if not course:
        return ERROR403

    enrollment_query = datastore_client.query(kind=ENROLLMENTS)
    enrollment_query.add_filter("course_id", "=", course_id)
    enrollments = list(enrollment_query.fetch())
    for e in enrollments:
        datastore_client.delete(e.key)

    datastore_client.delete(course_key)
    return ('', 204)


@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_course_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401

    course_key = datastore_client.key(COURSES, course_id)
    course = datastore_client.get(course_key)
    if not course:
        return ERROR403

    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results:
        return ERROR403

    user = results[0]
    if user['role'] != 'admin' and user.key.id != course['instructor_id']:
        return ERROR403

    content = request.get_json()
    if 'add' not in content or 'remove' not in content:
        return ERROR400

    try:
        add_ids = [int(sid) for sid in content['add']]
        remove_ids = [int(sid) for sid in content['remove']]
    except ValueError:
        return {"Error": "Enrollment data is invalid"}, 409

    if set(add_ids) & set(remove_ids):
        return {"Error": "Enrollment data is invalid"}, 409

    for uid in add_ids + remove_ids:
        student = datastore_client.get(datastore_client.key(USERS, uid))
        if not student or student['role'] != 'student':
            return {"Error": "Enrollment data is invalid"}, 409

    for sid in add_ids:
        key = datastore_client.key(ENROLLMENTS, f"{sid}_{course_id}")
        entity = datastore.Entity(key=key)
        entity.update({"student_id": sid, "course_id": course_id})
        datastore_client.put(entity)

    for sid in remove_ids:
        key = datastore_client.key(ENROLLMENTS, f"{sid}_{course_id}")
        datastore_client.delete(key)

    return ('', 200)

@app.route('/courses/<int:course_id>/students', methods=['GET'])
def get_course_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except:
        return ERROR401

    course_key = datastore_client.key(COURSES, course_id)
    course = datastore_client.get(course_key)
    if not course:
        return ERROR403

    query = datastore_client.query(kind=USERS)
    query.add_filter("sub", "=", payload["sub"])
    results = list(query.fetch())
    if not results:
        return ERROR403

    user = results[0]
    if user['role'] != 'admin' and user.key.id != course['instructor_id']:
        return ERROR403

    enrollment_query = datastore_client.query(kind=ENROLLMENTS)
    enrollment_query.add_filter("course_id", "=", course_id)
    enrollments = list(enrollment_query.fetch())

    student_ids = [e['student_id'] for e in enrollments]
    return jsonify(student_ids), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)