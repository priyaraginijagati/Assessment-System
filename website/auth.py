import csv,re
from sentence_transformers import util,SentenceTransformer
from io import TextIOWrapper
import time
import jwt
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, flash, session, redirect, url_for
from .models import TestResultData, User,TestResult,TopicResult,Topic,CorrectQuestion,Subject,Login
from . import mongo2
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app

auth = Blueprint('auth', __name__)

def get_questions(num_questions,sub):
    questions=[]
    if(sub=='java'):

        random = mongo2.db.java.aggregate([
            { '$sample': { 'size': num_questions } },
            { '$project': { '_id': 0, 'Question': 1 } }
        ])
    else:
        random = mongo2.db.python.aggregate([
            { '$sample': { 'size': num_questions } },
            { '$project': { '_id': 0, 'Question': 1 } }
        ])
    for r in random:
        question=r['Question']
        questions.append(question)
    return list(questions)


def get_random_questions(num_questions, sub):

    token=session.get('token')
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects(id=user_id).first()
    email=user.email
    existing_questions = mongo2.db.correct_question.find_one({'email':email})  # Fetch the existing questions from the email.subjects collection
    print(existing_questions)
    if not existing_questions:
        questions=get_questions(num_questions,sub)
        return questions

    subjects = existing_questions.get('subjects', [])

    selected_questions = []

    for subject in subjects:
        if subject['subject'] == sub:
            topics = subject.get('topics', [])

            for topic in topics:
                questions = topic.get('easy', []) + topic.get('medium', []) + topic.get('hard', [])
                selected_questions.extend(questions)

    collection = mongo2.db.java if sub == 'java' else mongo2.db.python

    questions = []

    while len(questions) < num_questions:
        random_question_cursor = collection.aggregate([
            { '$sample': { 'size': 1 } },
            { '$project': { '_id': 0, 'Question': 1 } }
        ])

        for document in random_question_cursor:
            question_text = document['Question']

            if question_text not in selected_questions and question_text not in questions:
                questions.append(question_text)
   
    return list(questions)



@auth.route('/java')
def java():
    num_questions = 10  # Specify the number of questions needed
    questions = get_random_questions(num_questions,sub='java')
    print(questions)
    return render_template('java.html', questions=questions,num_questions=num_questions)

@auth.route('/python')
def python():
    num_questions = 10  # Specify the number of questions needed
    questions = get_random_questions(num_questions,sub='python')
    return render_template('python.html', questions=questions,num_questions=num_questions)

@auth.route('/')
def home():
    token = session.get('token')
    if token:
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload['user_id']
            user = User.objects(id=user_id).first()
            session['role']=user.role
            if user:
                last_activity = session.get('last_activity')
                if last_activity and time.time() - last_activity > 24 * 60 * 60: 
                    session.pop('token', None)  
                    flash('Session expired. Please log in again.')
                    return redirect(url_for('auth.login'))
                login_data=Login.objects(email=user.email).first()
                if(login_data.password_count==0):
                    return render_template("cpassword.html",login_data=login_data,user=user)
                else:
                    return render_template("userdash.html", user=user,login_data=login_data)
            else:
                flash('Invalid token')
        except jwt.ExpiredSignatureError:
            flash('Token expired')
            return redirect(url_for('auth.logout'))
        except jwt.InvalidTokenError:
            flash('Invalid token')
            return redirect(url_for('auth.logout'))

    return redirect(url_for('auth.login'))


@auth.route("/uploadpage")
def uploadpage():
    return render_template("upload.html")


ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@auth.route('/users_upload',methods=['GET', 'POST'])
def users_upload():
    uploaded_count = 0
    skipped_count = 0
    user='users'

    if request.method == 'POST':
        csv_file = request.files.get('csv_file')

        if csv_file and allowed_file(csv_file.filename):
            
            csv_data = TextIOWrapper(csv_file, encoding='utf-8')
            reader = csv.DictReader(csv_data)
            cleaned_data = [{key.strip('\ufeff'): value for key, value in row.items()} for row in reader]
            for row in cleaned_data:
                email = row.get('email')
                if not email:
                    skipped_count += 1
                    continue  
                existing_record = mongo2.db.users.find_one({'email': email})
                if existing_record is not None:
                    skipped_count += 1
                    continue 

                else:
                    password=generate_password_hash(row.get('password'), method='sha256')
                    row['password']=password
                    mongo2.db.users.insert_one(row)
                    uploaded_count += 1
    return render_template("users_upload.html",uploaded_count=uploaded_count,skipped_count=skipped_count)

@auth.route('/upload', methods=['GET', 'POST'])
def upload():
    uploaded_count = 0
    skipped_count = 0

    if request.method == 'POST':
        subject = request.form.get('subject')
        csv_file = request.files.get('csv_file')

        if csv_file and allowed_file(csv_file.filename):
            
            csv_data = TextIOWrapper(csv_file, encoding='utf-8')
            reader = csv.DictReader(csv_data)

            for row in reader:
                Question = row.get('Question')
                if not Question:
                    skipped_count += 1
                    continue  
                existing_record = mongo2.db[subject].find_one({'Question': Question})
                if existing_record is not None:
                    skipped_count += 1
                    continue 

                else:
                    mongo2.db[subject].insert_one(row)
                    uploaded_count += 1
                
    return render_template('upload.html', uploaded_count=uploaded_count, skipped_count=skipped_count)



@auth.route('/users',methods=['POST','GET'])
def users():
    users_collection=mongo2.db.users
    users=list(users_collection.find())
    return render_template("users.html",users=users)



@auth.route('/evaluate', methods=['POST'])
def evaluate_answers():
    token = session.get('token')
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects(id=user_id).first()
    model_name = 'paraphrase-MiniLM-L6-v2'
    sentence_transformer = SentenceTransformer(model_name)
    subject = request.form.get('subject')
    user_answers = request.form.getlist('answer')
    questions = request.form.getlist('question')

    difficulty_dict = {}
    question_answers = {}
    question_topic={}

    for question in questions:
        doc = mongo2.db[subject].find_one({'Question': question})
        topic = doc.get('\ufeffTopic', '')  # Use get() and provide a default value
        difficulty = doc.get('Difficulty', '')
        answer = doc.get('Answer', '')
        difficulty_dict[question] = difficulty
        question_answers[question] = answer
        question_topic[question]=topic
          
    
    answer_embeddings = sentence_transformer.encode(list(question_answers.values()))

    difficulty_counts = {'Easy': {'Right': 0, 'Wrong': 0}, 'Medium': {'Right': 0, 'Wrong': 0}, 'Hard': {'Right': 0, 'Wrong': 0}}
    results = []
    correct = 0
 
    easy_topics = []
    medium_topics = []
    hard_topics = []
    for question, user_answer, answer_embedding in zip(questions, user_answers, answer_embeddings):
        difficulty = difficulty_dict[question]
        actual_embedding = answer_embedding

        user_embedding = sentence_transformer.encode([user_answer])[0]

        similarity = util.cos_sim(user_embedding, actual_embedding)
        percentage = float(similarity * 100)

        if percentage >= 70:
            correctness = 'Right'
            correct += 1
            difficulty_counts[difficulty]['Right'] += 1

            # Update counts for topics
            topic = question_topic[question]
            if difficulty == 'Easy':
                update_topic_counts(easy_topics, topic, True)
                save_correct_question(user.email,subject, topic, 'Easy', question)
            elif difficulty == 'Medium':
                update_topic_counts(medium_topics, topic, True)
                save_correct_question(user.email,subject, topic, 'Medium', question)
            elif difficulty == 'Hard':
                update_topic_counts(hard_topics, topic, True)
                save_correct_question(user.email,subject, topic, 'Hard', question)
        else:
            correctness = 'Wrong'
            difficulty_counts[difficulty]['Wrong'] += 1

            # Update counts for topics
            topic = question_topic[question]
            if difficulty == 'Easy':
                update_topic_counts(easy_topics, topic, False)
            elif difficulty == 'Medium':
                update_topic_counts(medium_topics, topic, False)
            elif difficulty == 'Hard':
                update_topic_counts(hard_topics, topic, False)

        result = {
            'question': question,
            'correctness': correctness
        }
        results.append(result)

    total_questions = len(questions)
    correct_easy_questions = sum(1 for r in results if r['correctness'] == 'Right' and difficulty_dict[r['question']] == 'Easy')
    correct_medium_questions = sum(1 for r in results if r['correctness'] == 'Right' and difficulty_dict[r['question']] == 'Medium')
    correct_hard_questions = sum(1 for r in results if r['correctness'] == 'Right' and difficulty_dict[r['question']] == 'Hard')

    total_easy_questions = sum(1 for difficulty in difficulty_dict.values() if difficulty == 'Easy')
    total_medium_questions = sum(1 for difficulty in difficulty_dict.values() if difficulty == 'Medium')
    total_hard_questions = sum(1 for difficulty in difficulty_dict.values() if difficulty == 'Hard')
    
        # Create a new test result object
    save_test_result(user.email, subject, correct, total_questions,
                     total_easy_questions, total_medium_questions, total_hard_questions,
                     correct_easy_questions, correct_medium_questions, correct_hard_questions,
                     easy_topics, medium_topics, hard_topics)
    return render_template('evaluate.html', correct=correct, total_questions=total_questions,
                           total_easy_questions=total_easy_questions, total_medium_questions=total_medium_questions,
                           total_hard_questions=total_hard_questions, correct_easy_questions=correct_easy_questions,
                           correct_medium_questions=correct_medium_questions,
                           correct_hard_questions=correct_hard_questions)






def update_topic_counts(topic_results, topic, is_correct):
    # Access the list within the ListField object
    topic_results_list = topic_results if isinstance(topic_results, list) else []

    # Check if the topic already exists in the list
    for topic_result in topic_results_list:
        if topic_result.topic == topic:
            if is_correct:
                topic_result.correct_answers += 1
            topic_result.number_of_questions += 1
            return

    # If the topic doesn't exist, create a new topic result object
    topic_result = TopicResult(topic=topic, correct_answers=1 if is_correct else 0, number_of_questions=1)
    topic_results_list.append(topic_result)

    # Save the updated list back to the ListField object if necessary
    if not isinstance(topic_results, list):
        topic_results = topic_results_list

    



def save_correct_question(email, subject, topic, difficulty, question):
    # Retrieve or create the correct_questions document for the email
    correct_questions = CorrectQuestion.objects(email=email).first()
    if not correct_questions:
        correct_questions = CorrectQuestion(email=email)
        correct_questions.save()

    # Find or create the subject document for the email
    subject_obj = next((s for s in correct_questions.subjects if s.subject == subject), None)
    if not subject_obj:
        subject_obj = Subject(subject=subject)
        correct_questions.subjects.append(subject_obj)

    # Find or create the topic document for the subject
    topic_obj = next((t for t in subject_obj.topics if t.topic == topic), None)
    if not topic_obj:
        topic_obj = Topic(topic=topic)
        subject_obj.topics.append(topic_obj)

    # Add the question to the corresponding difficulty level in the topic document
    if difficulty == 'Easy':
        topic_obj.easy.append(question)
    elif difficulty == 'Medium':
        topic_obj.medium.append(question)
    elif difficulty == 'Hard':
        topic_obj.hard.append(question)

    # Save the changes
    correct_questions.save()




def save_test_result(email, subject, correct, total_questions,
                     total_easy_questions, total_medium_questions, total_hard_questions,
                     correct_easy_questions, correct_medium_questions, correct_hard_questions,
                     easy_topics, medium_topics, hard_topics):
    def existing_test_results():
        existing_test_results = TestResultData.objects(email=email).first()

        if existing_test_results:
            return len(existing_test_results.test_results) + 1
        else:
            return 1

    test_result = TestResult(
        subject=subject,
        test_number=str(existing_test_results()),
        correct=correct,
        total_questions=total_questions,
        total_easy_questions=total_easy_questions,
        total_medium_questions=total_medium_questions,
        total_hard_questions=total_hard_questions,
        correct_easy_questions=correct_easy_questions,
        correct_medium_questions=correct_medium_questions,
        correct_hard_questions=correct_hard_questions,
        date=datetime.now().strftime("%Y-%m-%d"),
        time=datetime.now().strftime("%H:%M:%S"),
        easy_topics=easy_topics,
        medium_topics=medium_topics,
        hard_topics=hard_topics
    )

    existing_test_results = TestResultData.objects(email=email).first()

    if existing_test_results:
        existing_test_results.test_results.append(test_result)
        existing_test_results.save()
    else:
        test_results_data = TestResultData(email=email, test_results=[test_result])
        test_results_data.save()

    
@auth.route('/analysis',methods=["POST", "GET"])
def analysis():
    token = session.get('token')
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects(id=user_id).first()
    email=user.email
    correct_questions=CorrectQuestion.objects(email=email).first()
    
    correct_results = correct_questions.subjects if correct_questions else []
    print(correct_results)
    return render_template("analysis.html",correct_results=correct_results)


@auth.route('/student_analysis',methods=["POST", "GET"])
def student_analysis():
    email=request.args.get('email')
    correct_questions=CorrectQuestion.objects(email=email).first()
    correct_results = correct_questions.subjects if correct_questions else []
    print(correct_results)
    return render_template("analysis.html",correct_results=correct_results)



@auth.route('/result', methods=["POST", "GET"])
def result():
    token = session.get('token')
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects(id=user_id).first()
    email = user.email

    # Retrieve the test results from the database
    test_results_data = TestResultData.objects(email=email).first()
    test_results = test_results_data.test_results if test_results_data else []

    return render_template("result.html", test_results=test_results)


@auth.route('/change_password',methods=['GET','POST'])
def change_password():
    email=request.form.get('email')
    new_password=request.form.get('new_password')
    current_password=request.form.get('current_password')
    confirm_password=request.form.get('confirm_password')

    data=Login.objects(email=email).first()
    signup=User.objects(email=email).first()
    if not(new_password == confirm_password):
        flash("The New Password must be same as Confirm Password")
    elif not re.search(r'[A-Z]', new_password):
        flash("The Password should have a Upper Case Letter")
    elif not re.search(r'\d', new_password):
        flash("The Password should have a Digit")
    else:
        new_password=generate_password_hash(new_password, method='sha256')
        signup['password']=new_password
        signup.save()
        data.password_count +=1
        data.save()
        flash("password changed")
    return redirect(url_for('auth.home'))

@auth.route('/login', methods=["GET", "POST"])
def login():
    if 'token' in session:
        return redirect(url_for('auth.home'))
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.objects(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully')
                # Generating token
                token = jwt.encode(
                    {
                        'user_id': str(user.id),
                        'email': user.email,
                        'role': user.role,
                        'exp': datetime.utcnow() + timedelta(days=1)  # Token expiration time -1 day
                    },
                    current_app.config['SECRET_KEY'],  # Use your secret key
                    algorithm='HS256'# Hashing algorithm
                )
                session['token'] = token
                login_data = Login.objects(email=email).first()
                if login_data:
                    pass
                else:
    # Create a new Login document
                    new_login = Login(email=email, password_count=0)
                    new_login.save()
                return redirect(url_for('auth.home'))
            else:
                flash('Incorrect password')
        else:
            flash('Email does not exist')

    return render_template("login.html")




@auth.route("/profile")
def profile():
    token=session.get('token')
    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects(id=user_id).first()
    return render_template('profile.html',user=user)

@auth.route('/logout')
def logout():
    session.pop('token', None)
    session.pop('role', None)
    return redirect(url_for('auth.login'))

@auth.route('/signup', methods=["GET", "POST"])
def signup():
    if 'user_id' in session:
        return redirect(url_for('views.home'))
    elif request.method == 'POST':
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        user = User.objects(email=email).first()
        if user:
            flash('Email already exists')
        elif len(email) < 4:
            flash('Invalid email')
        elif len(firstName) < 4:
            flash('Username too short')
        elif len(password1) < 6:
            flash('Password is too short')
        elif password2 != password1:
            flash("Passwords don't match")
        else:
            new_user = User(
                email=email,
                first_name=firstName,
                password=generate_password_hash(password1, method='sha256'),
                role='admin' if email == 'admin@gmail.com' else 'student'
            )
            new_user.save()
            flash('Sign up successful')
            return redirect(url_for('auth.home'))

    return render_template("signup.html")