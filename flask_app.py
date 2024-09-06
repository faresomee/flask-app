from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
# from tensorflow.keras.models import load_model
import uuid

import jwt
import datetime
import h5py
import numpy as np
from PIL import Image
import io
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # استخدم مفتاح سري قوي

# In-memory data store
users = {}

# Signup endpoint
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    phone_number = data.get('phone_number')

    if username in users:
        return jsonify({"message": "Username already exists!"}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)
    
    # Store user data
    users[username] = {
        'password': hashed_password,
        'username':username,
        'email': email,
        'phone_number': phone_number
    }
    print(f"Stored users: {users}")

    return jsonify({"message": "Signup successful!"}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username not in users or not check_password_hash(users[username]['password'], password):
        return jsonify({"message": "Invalid username or password!"}), 401

    # Generate JWT token
    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # صلاحية التوكن لساعة واحدة
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        "message": "Login successful!",
        "token": token
    }), 200

# Protected route example
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Token is missing!"}), 403

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        username = data['username']
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 403

    return jsonify({
        "message": f"Welcome {username}!",
        "email": users[username]['email'],
        "phone_number": users[username]['phone_number']
    }), 200


from flask import Flask, request, jsonify
import pickle
import numpy as np


# تحميل النموذج المدرب
with open('/savemodel.sav', 'rb') as file:
    model = pickle.load(file)

@app.route('/predict_dementia', methods=['POST'])
def predict_dementia():
    try:
        # تحقق من أن نوع المحتوى هو JSON
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        # الحصول على البيانات من JSON
        data = request.get_json()

        # التحقق من وجود جميع الحقول المطلوبة
        required_fields = ['VISIT', 'MR_DAILY', 'SEX', 'AGE', 'EDUC', 'SES', 'MMSE', 'CDR', 'ETIV', 'NWBV', 'ASF']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"})

        # استخراج الميزات وإعدادها للتنبؤ
        features = [
            data['VISIT'],
            data['MR_DAILY'],
            data['SEX'],
            data['AGE'],
            data['EDUC'],
            data['SES'],
            data['MMSE'],
            data['CDR'],
            data['ETIV'],
            data['NWBV'],
            data['ASF']
        ]
        features = np.array(features).reshape(1, -1)

        # إجراء التنبؤ
        prediction = model.predict(features)[0]
        prediction = int(prediction)


        # تحويل التنبؤ إلى استجابة JSON
        return jsonify({"dementia_prediction": prediction})

    except Exception as e:
        # التقاط جميع الاستثناءات وإرجاع رسالة خطأ
        return jsonify({"error": str(e)})





# # فتح ملف h5 (يجب أن يكون النموذج محفوظًا بطريقة يمكن لـ h5py قراءتها)
# def load_model_h5(image_model):
#     return h5py.File(image_model, 'r')

# # قراءة البيانات من النموذج
# def predict_from_model(image_model, data):
#     # قراءة البيانات من النموذج (قد تحتاج إلى التعديل وفقًا لهيكلية النموذج)
#     weights = model['model_weights'] # هذا مسار افتراضي قد تحتاج إلى تعديله بناءً على هيكلية النموذج
#     # معالجة البيانات هنا حسب الحاجة
#     # return prediction
#     pass

# # نقطة نهاية للتنبؤ
# @app.route('/predict', methods=['POST'])
# def predict():
#     if 'file' not in request.files:
#         return jsonify({"message": "No file part in the request"}), 400

#     file = request.files['file']
    
#     if file.filename == '':
#         return jsonify({"message": "No selected file"}), 400

#     try:
#         img = Image.open(io.BytesIO(file.read()))
#         print("Image opened successfully.")

#         img = img.resize((128, 128))  # تأكد من ضبط حجم الصورة كما هو مطلوب من قبل 
#         print("Image resized to 128x128.")

#         img_array = np.array(img)
#         img_array = np.expand_dims(img_array, axis=0)
#         img_array = img_array / 255.0

#         model = load_model_h5('image_model.h5')
#         print("Model loaded successfully.")
#         print(f"Image array shape: {img_array.shape}")
#         predictions = model.predict_on_batch(img_array)
#         # predictions = model.predict(img_array)        
#         print("Model prediction completed.")
#         predicted_class = np.argmax(predictions, axis=1)[0]

#         # بناء استجابة التنبؤ بناءً على نموذجك
#         response = {
#         "predicted_class": predictions.tolist(),  # إذا كانت النتيجة مصفوفة، استخدم tolist()
#         }
        
#         return jsonify(response), 200
#     except Exception as e:
#         print(f"An error occurred: {str(e)}")
#         return jsonify({"error": str(e)}), 500
#     ############################Create New Password ###################################
# users = {
#     "example_user": {
#         "password": generate_password_hash("old_password"),
#         "email": "user@example.com",
#         "phone": "1234567890"
#     }
# }

# Endpoint to update password
@app.route('/update-password', methods=['POST'])
def update_password():
    data = request.json
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not username or not old_password or not new_password:
        return jsonify({"message": "Missing username, old password, or new password."}), 400

    user = users.get(username)

    if not user or not check_password_hash(user['password'], old_password):
        return jsonify({"message": "Invalid username or password."}), 401

    # Hash the new password and update the user's password
    user['password'] = generate_password_hash(new_password)
    
    return jsonify({"message": "Password updated successfully!"}), 200

###########################################forgetpassword##################################################
users = {
    "example_user": {
        "password": "hashed_password",
        "email": "user@example.com",
        "phone": "1234567890",
        "reset_token": None
    }
}

# Endpoint to request password reset
@app.route('/request-reset-password', methods=['POST'])
def request_reset_password():
    data = request.json
    email = data.get('email')

    # Find the user by email
    user = next((u for u in users.values() if u['email'] == email), None)

    if not user:
        return jsonify({"message": "Email address not found."}), 404

    # Generate a unique reset token
    reset_token = str(uuid.uuid4())
    user['reset_token'] = reset_token

    # In a real application, you would send this token to the user's email
    # For simplicity, we'll just return it in the response
    return jsonify({"message": "Reset token generated.", "reset_token": reset_token}), 200
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')

    # Find the user by reset token
    user = next((u for u in users.values() if u['reset_token'] == reset_token), None)

    if not user:
        return jsonify({"message": "Invalid reset token."}), 400

    # Update the user's password
    user['password'] = generate_password_hash(new_password)
    user['reset_token'] = None  # Clear the reset token

    return jsonify({"message": "Password reset successfully."}), 200

####################################compare###########################################


# Endpoint to compare user input with stored data
@app.route('/compare', methods=['POST'])
def compare():
    data = request.json
    username = data.get('username')
    email = data.get('email')  # مثال على مقارنة البريد الإلكتروني

    if username not in users:
        return jsonify({"message": "User not found"}), 404

    stored_email = users[username]["email"]

    if stored_email != email:
        return jsonify({"message": "Data does not match!"}), 400

    return jsonify({"message": "Data matches successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True)








##############################Only_signup#####################################



# from flask import Flask, request, jsonify

# app = Flask(__name__)

# # Dummy data store (in-memory)
# users = {}

# @app.route('/signup', methods=['POST'])
# def signup():
#     # Get the JSON data from the request
#     data = request.json

#     # Extract username and password from the request data
#     username = data.get('username')
#     password = data.get('password')

#     # Check if username already exists
#     if username in users:
#         return jsonify({"message": "Username already exists!"}), 400

#     # Add the new user to the data store
#     users[username] = password

#     # Return a success message
#     return jsonify({"message": "Signup successful!"}), 201

# if __name__ == '__main__':
#     app.run(debug=True)
#############################Only_login################################################
# from flask import Flask, request, jsonify

# app = Flask(__name__)

# if __name__ == '__main__':
#     app.run(debug=True)


# app = Flask(__name__)

# # Dummy data for users
# users = {
#     "user1": "password1",
#     "user2": "password2"
# }

# @app.route('/login', methods=['POST'])
# def login():
#     # Get the JSON data from the request
#     data = request.json

#     # Extract username and password from the request data
#     username = data.get('username')
#     password = data.get('password')

#     # Verify if the username exists and the password matches
#     if username in users and users[username] == password:
#         # If successful, return a success response
#         return jsonify({"message": "Login successful!"}), 200
#     else:
#         # If login fails, return an error response
#         return jsonify({"message": "Invalid username or password!"}), 401

# if __name__ == '__main__':
#     app.run(debug=True)




