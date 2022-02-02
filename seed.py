from faker import Faker
from poison_bar import db, UserModel, PostModel
from werkzeug.security import generate_password_hash
from random import random
db.create_all()

fake = Faker()
for i in range(1, 200):
    user = UserModel(username=fake.name(), email=fake.email(), password=generate_password_hash("password"))
    db.session.add(user)
    db.session.commit()


for i in range(1, 200):
    post = PostModel(name=fake.paragraph(nb_sentences=1), recipe=fake.text(), user_id=abs(i-200))
    db.session.add(post)
    db.session.commit()