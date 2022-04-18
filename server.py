from flask import Flask, render_template, request, flash, url_for, redirect
from flask_login import UserMixin, login_user, logout_user, LoginManager, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.getcwd()}/users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'TEMP BULLSHIT AH1235412'
app.config['TESTING'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
HASHING_METHOD = 'pbkdf2:sha256'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(), nullable=False)
    tasks_do = db.Column(db.String())
    tasks_done = db.Column(db.String())
    tasks_doing = db.Column(db.String())
    undo_data = db.Column(db.String())
    active_session = db.Column(db.Integer)


def grab_tasks_lists():
    if not current_user.is_active:
        raise Exception('Attempted to get tasks without an active user.')
    return [task_set.split('\n') if task_set else None for task_set in
            (current_user.tasks_do, current_user.tasks_doing, current_user.tasks_done)]


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def homepage():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        user_email = request.form.get('email').lower()  # emails ain't case-sensitive!
        user_password = request.form.get('password')
        if not user_email:
            flash('No email address entered.')
        elif user_email not in [user.email for user in User.query.all()]:
            flash('Email not registered.')
        else:
            attempted_user = User.query.filter_by(email=user_email)[0]
            if check_password_hash(pwhash=attempted_user.password_hash,
                                   password=user_password):
                login_user(attempted_user)
                return redirect(f'../personal/{current_user.username}')
            else:
                flash('Incorrect password')
    return render_template('login_register.html', is_login=True)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Gotta be careful with this. Emails ain't case-sensitive.
        new_email = request.form.get('email').lower()
        new_password = request.form.get('password')
        if not (new_email and new_password):
            flash('You need an email and a password to register.')
        elif new_email in [user.email for user in User.query.all()]:
            flash("Email already registered.")
        else:
            if new_password != request.form.get('password-con'):
                flash("Passwords don't match.")
            else:
                new_user = User()
                new_user.email = new_email
                new_user.password_hash = generate_password_hash(password=new_password,
                                                                method=HASHING_METHOD,
                                                                salt_length=25)
                new_user.username = new_email.split('@')[0]
                new_user.active_session = 0
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login_page'))
    return render_template('login_register.html', is_login=False)


@app.route('/personal/<username>', methods=['GET', 'POST'])
@login_required
def user_page(username):
    if current_user.username != username:
        return redirect(f'/personal/{current_user.username}')
    tasks = grab_tasks_lists()
    titles = ['Do', 'Doing', 'Done']  # I tried really hard to find a way to do this ~ automatically
    # but alas it's pretty fiddly trying to get the name of a list
    buttons = ['Move to Doing', 'Move to Done', 'Delete Task']
    classes = ['carousel-item' for _ in range(3)]
    classes[current_user.active_session] += ' active'  # one of the carousel items has to be active for this to work.
    # the point of an active_session variable is so that the user remains on the same carousel item
    # after performing an action.
    if request.method == 'POST':
        added_task = request.form.get('task')
        if not current_user.tasks_do:
            current_user.tasks_do = added_task  # we have to initialize the shit so it ain't none
        else:
            current_user.tasks_do += '\n' + added_task
        current_user.active_session = 0
        db.session.commit()
        return redirect(url_for('user_page', username=username))
    return render_template('index.html', tasks=tasks, titles=titles, classes=classes, buttons=buttons)


@app.route('/personal/change_tasks/<task_set>/<task_id>')
@login_required
def task_func(task_set, task_id):
    do, doing, done = grab_tasks_lists()
    task_id = int(task_id)
    if task_set == 'Do':
        task = do[task_id]
        if not current_user.tasks_doing:
            current_user.tasks_doing = task
        else:
            current_user.tasks_doing += '\n' + task
        do.pop(task_id)
        current_user.tasks_do = "\n".join(do)
        current_user.active_session = 0
    elif task_set == 'Doing':
        task = doing[task_id]
        if not current_user.tasks_done:
            current_user.tasks_done = task
        else:
            current_user.tasks_done += '\n' + task
        doing.pop(task_id)
        current_user.tasks_doing = "\n".join(doing)
        current_user.active_session = 1
    else:  # task_set == 'Done'
        done.pop(task_id)
        current_user.tasks_done = "\n".join(done)
        current_user.active_session = 2
    db.session.commit()
    return redirect(url_for('user_page', username=current_user.username))


@app.route('/personal/logout')
@login_required
def logout():
    logout_user()
    return redirect('../')


if __name__ == '__main__':
    app.run(debug=True)
