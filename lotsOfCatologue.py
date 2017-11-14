from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from dbSetup import Sport, Base, CatologueItem, User

engine = create_engine('sqlite:///sportCatologue.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Catologue for Hockey
sport1 = Sport(user_id=1, name="Hockey")

session.add(sport1)
session.commit()

catologueItem2 = CatologueItem(user_id=1, name="stick", description="hit a ball",
                               sport=sport1)

session.add(catologueItem2)
session.commit()


catologueItem1 = CatologueItem(user_id=1, name="ice", description="you need ice to play hockey",
                     sport=sport1)

session.add(catologueItem1)
session.commit()


# Catologue for Soccer
sport1 = Sport(user_id=1, name="Soccer")

session.add(sport1)
session.commit()


catologueItem1 = CatologueItem(user_id=1, name="socks", description="wear socks",
                      sport=sport1)

session.add(catologueItem1)
session.commit()

catologueItem2 = CatologueItem(user_id=1, name="t-shirt",
                     description="wear T-shirt", sport=sport1)

session.add(catologueItem2)
session.commit()

catologueItem3 = CatologueItem(user_id=1, name="shorts", description="wear shorts",
                     sport=sport1)

session.add(catologueItem3)
session.commit()


# Catologue for basketball
sport1 = Sport(user_id=1, name="basketball")

session.add(sport1)
session.commit()


catologueItem1 = CatologueItem(user_id=1, name="basket ball", description="an orange ball",
                      sport=sport1)

session.add(catologueItem1)
session.commit()

catologueItem2 = CatologueItem(user_id=1, name="sneakers", description="shoes to protect you", sport=sport1)

session.add(catologueItem2)
session.commit()

catologueItem3 = CatologueItem(user_id=1, name="coach", description="guidance",
                     sport=sport1)

session.add(catologueItem3)
session.commit()


# Catologue for Snowboarding
sport1 = Sport(user_id=1, name="Snowboarding")

session.add(sport1)
session.commit()


catologueItem1 = CatologueItem(user_id=1, name="googles", description="protect your eyes", sport=sport1)

session.add(catologueItem1)
session.commit()

catologueItem2 = CatologueItem(user_id=1, name="snowboard", description="to snowboard", sport=sport1)

session.add(catologueItem2)
session.commit()


print "added menu items!"
