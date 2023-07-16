from flask import Flask,render_template
from flask_sqlalchemy import SQLAlchemy
from flask import request
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError,Email
from flask_bcrypt import Bcrypt
import numpy as np

app = Flask(__name__)

app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['FLASK_ENV'] = 'development'
app.config['SECRET_KEY'] = 'ItShouldBeALongStringOfRandomCharacters'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:!1357Gone1357@localhost:3306/gradedDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


import pickle


model = pickle.load(open('model.pkl', 'rb')) # loading the trained model
print(model)
# Assuming you have already trained your model and have the input data X





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

with app.app_context():
    db.create_all()



class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[
        InputRequired(), Length(min=4, max=20),Email()], render_kw={"placeholder": "email"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})


    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def hello():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print(form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print("user")
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                print(user)
                return redirect(url_for('dashboard'))
            else :
                print("wrong password")
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('entryform.html')

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    # retrieving values from form
    input_features = [float(x) for x in request.form.values()]
    print(input_features)
    cal_features = []
    cal_features.append(input_features[2])#Education

    cal_features.append(input_features[-2])#credit history
    cal_features.append(input_features[-1])#property area
    x1=((input_features[4])/((input_features[2])+1))#average Sal
    cal_features.append(x1)
    cal_features.append((input_features[5])/(x1*(input_features[-3])))#ratio=loanamount/(averagesal*numberOfTerms)
    print((input_features[5])/(x1*(input_features[-3])))
    final_features = [np.array(cal_features)]

    print(final_features, "hhhhhhhhhhhhhhhhhhhppppppppppppppppp###hhhhhhhhhhhhhhhhhhh")
    possible_amount=(x1*(input_features[-3])*1.15)


    prediction = model.predict(final_features)
    print(prediction)
    if prediction[0]=='y':
        prediction="Congratulations, your loan has been approved"
    if prediction[0] == 'n':
        prediction="Sorry, but you could apply upto",int(possible_amount)# making prediction
    return render_template('predict.html',
                           prediction_text='Predicted Class: {}'.format(prediction))  # rendering the predicted result


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password,email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
