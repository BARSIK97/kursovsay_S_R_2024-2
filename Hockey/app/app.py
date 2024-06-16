import datetime
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from mysqldb import DBConnector
from mysql.connector.errors import DatabaseError

import base64

app = Flask(__name__)
application = app
app.config.from_pyfile("config.py")

db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth"
login_manager.login_message = "Войдите, чтобы просматривать содержимое данной страницы"
login_manager.login_message_category = "warning"


class User(UserMixin):
    def __init__(self, user_id, login, role_id):
        self.id = user_id
        self.login = login
        self.role_id = role_id


CREATE_USER_FIELDS = [
    "login",
    "password",
    "last_name",
    "first_name",
    "middle_name",
    "phone",
    "email",
]
EDIT_USER_FIELDS = [
    "login",
    "password",
    "last_name",
    "first_name",
    "middle_name",
    "phone",
    "email",
]


def get_roles():
    query = "SELECT * FROM roles"

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        roles = cursor.fetchall()
    return roles


@login_manager.user_loader
def load_user(user_id):
    query = "SELECT user_id, login, role_id FROM users WHERE user_id=%s"

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()

    if user:
        return User(
            user.user_id, user.login, user.role_id
        )  # Используем имена атрибутов
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "GET":
        return render_template("auth.html")

    login = request.form.get("login", "")
    password = request.form.get("pass", "")
    remember = request.form.get("remember") == "on"

    query = "SELECT user_id, login, role_id FROM users WHERE login=%s AND password=SHA2(%s, 256)"

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (login, password))

        user = cursor.fetchone()

    if user:
        login_user(User(user.user_id, user.login, user.role_id), remember=remember)
        flash("Вы успешно вошли", category="success")
        target_page = request.args.get("next", url_for("index"))
        return redirect(target_page)

    flash("Введен неверный логин или пароль", category="danger")

    return render_template("auth.html")


@app.route("/account")
@login_required
def users():
    query = "SELECT users.* FROM users WHERE user_id=%s"
    
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (current_user.id,))
        user = cursor.fetchone()
    
    user_dict = dict(user._asdict())  # Преобразуем namedtuple в словарь
    if user.user_image:
        user_dict["user_image"] = base64.b64encode(user.user_image).decode("utf-8")
    
    return render_template("account.html", user=user_dict)

def get_form_data(required_fields):
    user = {}

    for field in required_fields:
        user[field] = request.form.get(field) or None

    return user


@app.route("/reg", methods=["GET", "POST"])
def reg():
    errors = None
    if request.method == "POST":
        user = get_form_data(
            [
                "login",
                "password",
                "last_name",
                "first_name",
                "middle_name",
                "phone",
                "email",
            ]
        )
        user["role_id"] = 1

        errors = validate_user_data(user)

        if not errors:
            user_image = None
            if "user_image" in request.files:
                file = request.files["user_image"]
            if file and file.filename != "":
                user_image = file.read()
            query = (
                "INSERT INTO users (login, password, last_name, first_name, middle_name, phone, email, role_id, user_image) "
                "VALUES (%(login)s, SHA2(%(password)s, 256), %(last_name)s, %(first_name)s, %(middle_name)s, %(phone)s, %(email)s, %(role_id)s, %(user_image)s)"
            )
            user["user_image"] = user_image
            try:
                with db_connector.connect().cursor(named_tuple=True) as cursor:
                    cursor.execute(query, user)
                    db_connector.connect().commit()
                    flash("Вы успешно зарегистрировались", category="success")
                    return redirect(url_for("auth"))
            except DatabaseError as error:
                flash(f"Ошибка регистрации пользователя: {error}", category="danger")
                db_connector.connect().rollback()

    return render_template("reg.html", user={}, errors=errors)


@app.route("/account/<int:user_id>/edit_user", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    query = ("SELECT * FROM users where user_id = %s")
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (user_id, ))
        user = cursor.fetchone()
    
    errors = None
    print(user_id)
    if request.method == "POST":
        updated_user = get_form_data(
            [
                "login",
                "last_name",
                "first_name",
                "middle_name",
                "phone",
                "email",
                "password",
            ]
        )
        print(updated_user)
        errors = validate_user_data(updated_user)

        if not errors:
            user_image = None
            if "user_image" in request.files:
                file = request.files["user_image"]
                if file and file.filename != "":
                    user_image = file.read()
            updated_user['user_id'] = user_id
            updated_user['user_image'] = user_image
            query = """
            UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, middle_name=%(middle_name)s,
                            phone=%(phone)s, email=%(email)s, user_image=%(user_image)s
            """
            if updated_user["password"]:
                query += ", password=SHA2(%(password)s, 256)"
            query += " WHERE user_id=%(user_id)s"

            try:
                with db_connector.connect().cursor(named_tuple=True) as cursor:
                    updated_user["user_id"] = user.user_id
                    cursor.execute(query, updated_user)
                    db_connector.connect().commit()
                    flash("Информация обновлена", category="success")
                    return redirect(url_for("account"))
            except DatabaseError as error:
                flash(f"Ошибка обновления информации: {error}", category="danger")
                db_connector.connect().rollback()

    return render_template("edit_user.html", user=user, errors=errors)


def validate_user_data(user):
    errors = {}

    if not user["login"] or len(user["login"]) <= 5 or not user["login"].isalnum():
        errors["login"] = (
            "Логин должен содержать не менее 5 символов и состоять только из латинских букв и цифр"
        )

    if "password" in user and user["password"]:
        password_errors = validate_password(user["password"])
        if password_errors:
            errors["password"] = password_errors

    if not user["last_name"]:
        errors["last_name"] = "Поле не может быть пустым"
    if not user["first_name"]:
        errors["first_name"] = "Поле не может быть пустым"
    if not user["phone"]:
        errors["phone"] = "Поле не может быть пустым"
    if not user["email"]:
        errors["email"] = "Поле не может быть пустым"

    return errors

import base64
@app.route("/ammunition")
@login_required
def ammunition():
    query = "SELECT * FROM goods"
    
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query)
        goods = cursor.fetchall()
    
    good_data = []
    for good in goods:
        good_dict = dict(good._asdict())
        if good.good_image:
            good_dict['good_image'] = base64.b64encode(good.good_image).decode('utf-8')
        good_data.append(good_dict)
    
    return render_template("ammunition.html", goods=good_data)

@app.route("/ammunition/<int:good_id>")
@login_required
def more(good_id):
    query = "SELECT * FROM goods WHERE good_id=%s"
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (good_id,))
        good = cursor.fetchone()
    
    good_dict = dict(good._asdict())
    if good.good_image:
        good_dict['good_image'] = base64.b64encode(good.good_image).decode('utf-8')
    
    return render_template("more.html", good=good_dict)


@app.route("/basket", methods=["GET", "POST"])
@login_required
def basket():
    if request.method == "POST":
        good_id = request.form.get("good_id")
        quantity = int(request.form.get("quantity"))
        price = request.form.get("price")
        user_id = current_user.id
        order_id = 0

        query_check_good = "SELECT good_amount FROM goods WHERE good_id = %s"
        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute(query_check_good, (good_id,))
            good = cursor.fetchone()
            if good and good.good_amount < quantity:
                flash(
                    "Товар закончился или недостаточное количество на складе",
                    category="danger",
                )
                return redirect(url_for("ammunition"))

        query_check = """
        SELECT booking_id, amount
        FROM booking
        WHERE user_id = %s AND good_id = %s AND order_id = %s
        """
        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute(query_check, (user_id, good_id, order_id))
            existing_booking = cursor.fetchone()

        if existing_booking:
            new_amount = existing_booking.amount + quantity
            query_update = """
            UPDATE booking
            SET amount = %s
            WHERE booking_id = %s
            """
            try:
                with db_connector.connect().cursor(named_tuple=True) as cursor:
                    cursor.execute(
                        query_update, (new_amount, existing_booking.booking_id)
                    )
                    db_connector.connect().commit()
                flash("Количество товара в корзине обновлено", category="success")
            except DatabaseError as error:
                flash(
                    f"Ошибка при обновлении количества товара в корзине: {error}",
                    category="danger",
                )
                db_connector.connect().rollback()
        else:
            query_insert = """
            INSERT INTO booking (order_id, user_id, good_id, amount, price)
            VALUES (%s, %s, %s, %s, %s)
            """
            try:
                with db_connector.connect().cursor(named_tuple=True) as cursor:
                    cursor.execute(
                        query_insert, (order_id, user_id, good_id, quantity, price)
                    )
                    db_connector.connect().commit()
                    query_update_amount = """
                    UPDATE goods
                    SET good_amount = good_amount - %s
                    WHERE good_id = %s
                    """
                    cursor.execute(query_update_amount, (quantity, good_id))
                    db_connector.connect().commit()
                flash("Товар добавлен в корзину", category="success")
            except DatabaseError as error:
                flash(
                    f"Ошибка при добавлении товара в корзину: {error}",
                    category="danger",
                )
                db_connector.connect().rollback()

        return redirect(url_for("ammunition"))

    user_id = current_user.id
    query = """
    SELECT goods.good_id, goods.good_name, booking.amount, booking.price, booking.booking_id
    FROM booking
    JOIN goods ON booking.good_id = goods.good_id
    WHERE booking.user_id = %s and booking.view_status=0
    """
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (user_id,))
        basket_items = cursor.fetchall()

    return render_template("basket.html", basket_items=basket_items)


@app.route("/basket/delete/<int:booking_id>", methods=["POST"])
@login_required
def delete_from_basket(booking_id):
    query_select = (
        "SELECT good_id, amount FROM booking WHERE booking_id=%s AND user_id=%s"
    )
    query_delete = (
        "DELETE from booking WHERE booking_id=%s AND user_id=%s AND order_id=0"
    )
    query_update_good = (
        "UPDATE goods SET good_amount = good_amount + %s WHERE good_id=%s"
    )
    try:
        with db_connector.connect().cursor(named_tuple=True) as cursor:

            cursor.execute(query_select, (booking_id, current_user.id))
            booking_item = cursor.fetchone()

            if booking_item:
                good_id = booking_item.good_id
                amount = booking_item.amount

                cursor.execute(query_delete, (booking_id, current_user.id))

                cursor.execute(query_update_good, (amount, good_id))

                db_connector.connect().commit()
                flash("Товар удален из корзины", category="success")
            else:
                flash("Товар не найден в корзине", category="danger")
    except DatabaseError as error:
        flash(f"Ошибка при удалении товара из корзины: {error}", category="danger")
        db_connector.connect().rollback()

    return redirect(url_for("basket"))


@app.route("/make_ord", methods=["GET", "POST"])
@login_required
def make_ord():
    user_id = current_user.id

    query_basket = """
    SELECT goods.good_id, goods.good_name, booking.amount, booking.price
    FROM booking
    JOIN goods ON booking.good_id = goods.good_id
    WHERE booking.user_id = %s and view_status=0
    """
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query_basket, (user_id,))
        basket_items = cursor.fetchall()

    total_quantity = sum(item.amount for item in basket_items)
    total_price = sum(item.amount * float(item.price) for item in basket_items)

    discount = 0
    discount_message = "Если вы наберете больше 3-х товаров, то получите скидку в 10%.Скидка на доставку не распространяется!"
    if total_quantity > 3:
        discount = 0.1
        discount_message = "Вы покупаете больше 3-х товаров, вам скидка в 10% только на товары, не включая стоимсоть доставки!!"
        total_price = total_price * (1 - discount)

    query_delivery = "SELECT delivery_id, delivery_name, delivery_price FROM delivery"
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query_delivery)
        delivery_options = cursor.fetchall()

    if request.method == "POST":
        delivery_id = int(request.form.get("delivery_id"))
        address = request.form.get("address")

        selected_delivery = next(
            (
                delivery
                for delivery in delivery_options
                if delivery.delivery_id == delivery_id
            ),
            None,
        )
        if not selected_delivery:
            flash("Ошибка выбора доставки", category="danger")
            return redirect(url_for("make_ord"))

        delivery_price = selected_delivery.delivery_price

        if delivery_price > 0:
            total_price += delivery_price

        if delivery_id == 1:
            address = "1-й Балтийский переулок 6/21"

        order_date = datetime.date.today()
        status_id = 1
        insert_order_query = """
        INSERT INTO orders (user_id, delivery_id, address, order_date, final_price, status_id)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        update_booking_query = """
        UPDATE booking
        SET view_status = 1, order_id = (SELECT MAX(order_id) FROM orders)
        WHERE user_id = %s and booking.order_id=0
        """
        try:
            with db_connector.connect().cursor(named_tuple=True) as cursor:
                cursor.execute(
                    insert_order_query,
                    (user_id, delivery_id, address, order_date, total_price, status_id),
                )
                cursor.execute(update_booking_query, (user_id,))
                db_connector.connect().commit()
            flash("Заказ успешно оформлен!", category="success")
            return redirect(url_for("index"))
        except DatabaseError as error:
            flash(f"Ошибка при оформлении заказа: {error}", category="danger")
            db_connector.connect().rollback()

    return render_template(
        "make_ord.html",
        basket_items=basket_items,
        total_quantity=total_quantity,
        total_price=total_price,
        discount_message=discount_message,
        delivery_options=delivery_options,
    )


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user = current_user
    errors = None

    if request.method == "POST":
        updated_user = get_form_data(
            ["last_name", "first_name", "middle_name", "phone", "email"]
        )
        errors = validate_user_data(updated_user)

        if not errors:
            query = """
            UPDATE users SET last_name=%(last_name)s, first_name=%(first_name)s, middle_name=%(middle_name)s,
                            phone=%(phone)s, email=%(email)s
            WHERE user_id=%(user_id)s
            """
            try:
                with db_connector.connect().cursor(named_tuple=True) as cursor:
                    updated_user["user_id"] = user.id
                    cursor.execute(query, updated_user)
                    db_connector.connect().commit()
                    flash("Информация обновлена", category="success")
                    return redirect(url_for("account"))
            except DatabaseError as error:
                flash(f"Ошибка обновления информации: {error}", category="danger")
                db_connector.connect().rollback()

    return render_template("account.html", user=user, errors=errors)


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    query = "DELETE FROM users WHERE user_id=%s"
    try:
        with db_connector.connect().cursor(named_tuple=True) as cursor:
            cursor.execute(query, (user_id,))
            db_connector.connect().commit()
            logout_user()
            flash("Ваш аккаунт был удален", category="success")
            return redirect(url_for("index"))
    except DatabaseError as error:
        flash(f"Ошибка удаления пользователя: {error}", category="danger")
        db_connector.connect().rollback()
        return redirect(url_for("account"))


@app.route("/my_ord")
@login_required
def my_ord():
    query = """
    SELECT orders.order_id, orders.address, orders.order_date, orders.final_price, status.status_description
    FROM orders
    JOIN status ON orders.status_id = status.status_id
    WHERE orders.user_id = %s
    """

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (current_user.id,))
        orders = cursor.fetchall()
    return render_template("my_ord.html", orders=orders)


@app.route("/view_ord/<int:order_id>")
@login_required
def view_ord(order_id):
    query_order = """
    SELECT orders.order_id, orders.address, orders.order_date, orders.final_price, orders.delivery_id, status.status_description
    FROM orders
    JOIN status ON orders.status_id = status.status_id
    WHERE orders.order_id = %s AND orders.user_id = %s
    """

    query_items = """
    SELECT goods.good_name, booking.amount, booking.price
    FROM booking
    JOIN goods ON booking.good_id = goods.good_id
    WHERE booking.order_id = %s
    """

    query_delivery = """
    SELECT delivery_id, delivery_name, delivery_price
    FROM delivery
    WHERE delivery_id = %s
    """

    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query_order, (order_id, current_user.id))
        order = cursor.fetchone()

        cursor.execute(query_items, (order_id,))
        basket_items = cursor.fetchall()

        cursor.execute(query_delivery, (order.delivery_id,))
        delivery_option = cursor.fetchone()

    total_quantity = sum(item.amount for item in basket_items)
    total_price = sum(item.amount * float(item.price) for item in basket_items)

    discount = 0
    discount_message = "Если вы наберете больше 3-х товаров, то получите скидку в 10% Скидка на доставку не распространяется!"
    if total_quantity > 3:
        discount = 0.1
        discount_message = "Вы покупаете больше 3-х товаров, вам скидка в 10% только на товары, не включая стоимсоть доставки!!"
        total_price = total_price * (1 - discount)

    total_price += delivery_option.delivery_price

    return render_template(
        "view_ord.html",
        order=order,
        basket_items=basket_items,
        total_quantity=total_quantity,
        total_price=total_price,
        discount_message=discount_message,
        delivery_option=delivery_option,
    )


@app.route("/cancel_order/<int:order_id>")
@login_required
def cancel_order(order_id):
    update_query = """
    UPDATE orders
    SET status_id = 3
    WHERE order_id = %s
    """
    try:
        with db_connector.connect().cursor() as cursor:
            cursor.execute(update_query, (order_id,))
            db_connector.connect().commit()
            flash("Заказ успешно отменен", category="success")
    except DatabaseError as error:
        flash(f"Ошибка при отмене заказа: {error}", category="danger")
        db_connector.connect().rollback()

    return redirect(url_for("my_ord"))


@app.route("/complete_order/<int:order_id>")
@login_required
def complete_order(order_id):
    update_query = """
    UPDATE orders
    SET status_id = 2
    WHERE order_id = %s
    """
    try:
        with db_connector.connect().cursor() as cursor:
            cursor.execute(update_query, (order_id,))
            db_connector.connect().commit()
            flash("Заказ успешно завершен", category="success")
    except DatabaseError as error:
        flash(f"Ошибка при завершении заказа: {error}", category="danger")
        db_connector.connect().rollback()

    return redirect(url_for("my_ord"))


def validate_password(password):
    errors = []

    if len(password) <= 8 or len(password) > 128:
        errors.append("Пароль должен содержать от 8 до 128 символов")
    if not any(char.isupper() for char in password):
        errors.append("Пароль должен содержать хотя бы одну заглавную букву")
    if not any(char.islower() for char in password):
        errors.append("Пароль должен содержать хотя бы одну строчную букву")
    if not any(char.isdigit() for char in password):
        errors.append("Пароль должен содержать хотя бы одну цифру")
    no = "~!@#$%^&*_-+()[]{}><\/|\"'.,:;"
    if any(char in no for char in password):
        errors.append(
            "Пароль должен содержать только латинские или кириллические буквы, арабские цифры"
        )

    return errors





@app.route("/update_good/<int:good_id>", methods=["GET", "POST"])
@login_required
def update_good(good_id):
    query = "SELECT * FROM goods WHERE good_id = %s"
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute(query, (good_id,))
        good = cursor.fetchone()
    
    if request.method == "POST":
        good_name = request.form.get("good_name")
        good_description = request.form.get("good_description")
        good_price = request.form.get("good_price")
        good_amount = request.form.get("good_amount")
        good_image = None
        
        if 'good_image' in request.files:
            file = request.files['good_image']
            if file and file.filename != '':
                good_image = file.read()
        good_image = good_image
        query = """
        UPDATE goods
        SET good_name=%s, good_description=%s, good_price=%s, good_amount=%s, good_image=%s
        WHERE good_id=%s
        """
        
        try:
            with db_connector.connect().cursor() as cursor:
                cursor.execute(
                    query,
                    (good_name, good_description, good_price, good_amount, good_image, good_id)
                )
                db_connector.connect().commit()
                flash("Изменения сохранены", category="success")
                return redirect(url_for("ammunition"))
        except DatabaseError as error:
            flash(f"Ошибка при обновлении товара: {error}", category="error")
            db_connector.connect().rollback()
    else:
        return render_template("update_good.html", good=good)
    return redirect(url_for("ammunition"))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/secret")
@login_required
def secret():
    return render_template("secret.html")
