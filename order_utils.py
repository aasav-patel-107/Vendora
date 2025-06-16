from models import db, Order, OrderItem

def create_order(customer_id, cart_items, shipping_address):
    total = sum(item['price'] * item['quantity'] for item in cart_items)

    order = Order(
        customer_id=customer_id,
        shipping_address=shipping_address,
        total_amount=total,
        status='Pending'
    )
    db.session.add(order)
    db.session.flush()  # so order.id is available

    for item in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item['product_id'],
            product_name=item['product_name'],
            quantity=item['quantity'],
            price=item['price']
        )
        db.session.add(order_item)

    db.session.commit()
    return order
