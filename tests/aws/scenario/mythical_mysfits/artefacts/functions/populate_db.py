# Source adapted from: https://github.com/aws-samples/aws-modern-application-workshop/blob/python-cdk
from __future__ import print_function

import os

import boto3

client = boto3.client("dynamodb")

init_data = [
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "4e53920c-505a-4a90-a694-b9300791f0ae"},
                "Name": {"S": "Evangeline"},
                "Species": {"S": "Chimera"},
                "Description": {
                    "S": "Evangeline is the global sophisticate of the mythical world. You’d be hard pressed to find a more seductive, charming, and mysterious companion with a love for neoclassical architecture, and a degree in medieval studies. Don’t let her beauty and brains distract you. While her mane may always be perfectly coifed, her tail is ever-coiled and ready to strike. Careful not to let your guard down, or you may just find yourself spiraling into a dazzling downfall of dizzying dimensions."
                },
                "Age": {"N": "43"},
                "GoodEvil": {"S": "Evil"},
                "LawChaos": {"S": "Lawful"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/chimera_thumb.png"},
                "ProfileImageUri": {
                    "S": "https://www.mythicalmysfits.com/images/chimera_hover.png"
                },
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "2b473002-36f8-4b87-954e-9a377e0ccbec"},
                "Name": {"S": "Pauly"},
                "Species": {"S": "Cyclops"},
                "Description": {
                    "S": "Naturally needy and tyrannically temperamental, Pauly the infant cyclops is searching for a parental figure to call friend. Like raising any precocious tot, there may be occasional tantrums of thunder, lightning, and 100 decibel shrieking. Sooth him with some Mandrake root and you’ll soon wonder why people even bother having human children. Gaze into his precious eye and fall in love with this adorable tyke."
                },
                "Age": {"N": "2"},
                "GoodEvil": {"S": "Neutral"},
                "LawChaos": {"S": "Lawful"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/cyclops_thumb.png"},
                "ProfileImageUri": {
                    "S": "https://www.mythicalmysfits.com/images/cyclops_hover.png"
                },
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "0e37d916-f960-4772-a25a-01b762b5c1bd"},
                "Name": {"S": "CoCo"},
                "Species": {"S": "Dragon"},
                "Description": {
                    "S": "CoCo wears sunglasses at night. His hobbies include dressing up for casual nights out, accumulating debt, and taking his friends on his back for a terrifying ride through the mesosphere after a long night of revelry, where you pick up the bill, of course. For all his swagger, CoCo has a heart of gold. His loyalty knows no bounds, and once bonded, you’ve got a wingman (literally) for life."
                },
                "Age": {"N": "501"},
                "GoodEvil": {"S": "Good"},
                "LawChaos": {"S": "Chaotic"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/dragon_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/dragon_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "da5303ae-5aba-495c-b5d6-eb5c4a66b941"},
                "Name": {"S": "Gretta"},
                "Species": {"S": "Gorgon"},
                "Description": {
                    "S": "Young, fun, and perfectly mischievous, Gorgon is mostly tail. She's currently growing her horns and hoping for wings like those of her high-flying counterparts. In the meantime, she dons an umbrella and waits for gusts of wind to transport her across space-time. She likes to tell jokes in fluent Parseltongue, read the evening news, and shoot fireworks across celestial lines. If you like high-risk, high-reward challenges, Gorgon will be the best pet you never knew you wanted."
                },
                "Age": {"N": "31"},
                "GoodEvil": {"S": "Evil"},
                "LawChaos": {"S": "Neutral"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/gorgon_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/gorgon_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "a901bb08-1985-42f5-bb77-27439ac14300"},
                "Name": {"S": "Hasla"},
                "Species": {"S": "Haetae"},
                "Description": {
                    "S": "Hasla's presence warms every room. For the last 2 billion years, she's made visitors from far-away lands and the galaxy next door feel immediately at ease. Usually it's because of her big heart, but sometimes it's because of the fire she breathes—especially after eating garlic and starlight. Hasla loves togetherness, board games, and asking philosophical questions that leave people pondering the meaning of life as they fall asleep at night."
                },
                "Age": {"N": "2000000000"},
                "GoodEvil": {"S": "Good"},
                "LawChaos": {"S": "Neutral"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/haetae_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/haetae_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "b41ff031-141e-4a8d-bb56-158a22bea0b3"},
                "Name": {"S": "Snowflake"},
                "Species": {"S": "Yeti"},
                "Description": {
                    "S": "While Snowflake is a snowman, the only abomination is that he hasn’t been adopted yet. Snowflake is curious, playful, and loves to bound around in the snow. He likes winter hikes, hide and go seek, and all things Christmas. He can get a bit agitated when being scolded or having his picture taken and can occasionally cause devastating avalanches, so we don’t recommend him for beginning pet owners. However, with love, care, and a lot of ice, Snowflake will make a wonderful companion."
                },
                "Age": {"N": "13"},
                "GoodEvil": {"S": "Evil"},
                "LawChaos": {"S": "Neutral"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/yeti_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/yeti_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "3f0f196c-4a7b-43af-9e29-6522a715342d"},
                "Name": {"S": "Gary"},
                "Species": {"S": "Kraken"},
                "Description": {
                    "S": "Gary loves to have a good time. His motto? “I just want to dance.” Give Gary a disco ball, a DJ, and a hat that slightly obscures the vision from his top eye, and Gary will dance the year away which, at his age, is like one night in humanoid time. If you're looking for a low-maintenance, high-energy creature companion that never sheds and always shreds, Gary is just the kraken for you."
                },
                "Age": {"N": "2709"},
                "GoodEvil": {"S": "Neutral"},
                "LawChaos": {"S": "Chaotic"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/kraken_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/kraken_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "a68db521-c031-44c7-b5ef-bfa4c0850e2a"},
                "Name": {"S": "Nessi"},
                "Species": {"S": "Plesiosaurus"},
                "Description": {
                    "S": "Nessi is a fun-loving and playful girl who will quickly lock on to your love and nestle into your heart. While shy at first, Nessi is energetic and loves to play with toys such as fishing boats, large sharks, frisbees, errant swimmers, and wand toys. As an aquatic animal, Nessi will need deep water to swim in; at least 15 feet though she prefers 750. Nessi would be a wonderful companion for anyone seeking a loving, 1 ton ball of joy."
                },
                "Age": {"N": "75000000"},
                "GoodEvil": {"S": "Neutral"},
                "LawChaos": {"S": "Neutral"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/nessie_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/nessie_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "c0684344-1eb7-40e7-b334-06d25ac9268c"},
                "Name": {"S": "Atlantis"},
                "Species": {"S": "Mandrake"},
                "Description": {
                    "S": "Do you like long naps in the dirt, vegetable-like appendages, mind-distorting screaming, and a unmatched humanoid-like root system? Look no further, Atlantis is the perfect companion to accompany you down the rabbit hole! Atlantis is rooted in habitual power napping and can unleash a terse warning when awakened. Like all of us, at the end of a long nap, all Atlantis needs is a soothing milk or blood bath to take the edge off. If you're looking to take a trip, this mandrake is your ideal travel companion."
                },
                "Age": {"N": "100"},
                "GoodEvil": {"S": "Neutral"},
                "LawChaos": {"S": "Neutral"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/mandrake_thumb.png"},
                "ProfileImageUri": {
                    "S": "https://www.mythicalmysfits.com/images/mandrake_hover.png"
                },
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "ac3e95f3-eb40-4e4e-a605-9fdd0224877c"},
                "Name": {"S": "Twilight Glitter"},
                "Species": {"S": "Pegasus"},
                "Description": {
                    "S": "Twilight’s personality sparkles like the night sky and is looking for a forever home with a Greek hero or God. While on the smaller side at 14 hands, he is quite adept at accepting riders and can fly to 15,000 feet. Twilight needs a large area to run around in and will need to be registered with the FAA if you plan to fly him above 500 feet. His favorite activities include playing with chimeras, going on epic adventures into battle, and playing with a large inflatable ball around the paddock. If you bring him home, he’ll quickly become your favorite little Pegasus."
                },
                "Age": {"N": "6"},
                "GoodEvil": {"S": "Good"},
                "LawChaos": {"S": "Lawful"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/pegasus_thumb.png"},
                "ProfileImageUri": {
                    "S": "https://www.mythicalmysfits.com/images/pegasus_hover.png"
                },
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "33e1fbd4-2fd8-45fb-a42f-f92551694506"},
                "Name": {"S": "Cole"},
                "Species": {"S": "Phoenix"},
                "Description": {
                    "S": "Cole is a loving companion and the perfect starter pet for kids. Cole’s tears can fix almost any boo-boo your children may receive (up to partial limb amputation). You never have to worry about your kids accidentally killing him as he’ll just be reborn in a fun burst of flame if they do. Even better, Cole has the uncanny ability to force all those around him to tell the truth, so say goodbye to fibs about not eating a cookie before dinner or where your teenager actually went that night. Adopt him today and find out how he will be the perfect family member for you, your children, their children, their children’s children, and so on."
                },
                "Age": {"N": "1393"},
                "GoodEvil": {"S": "Good"},
                "LawChaos": {"S": "Chaotic"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/phoenix_thumb.png"},
                "ProfileImageUri": {
                    "S": "https://www.mythicalmysfits.com/images/phoenix_hover.png"
                },
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
    {
        "PutRequest": {
            "Item": {
                "MysfitId": {"S": "b6d16e02-6aeb-413c-b457-321151bb403d"},
                "Name": {"S": "Rujin"},
                "Species": {"S": "Troll"},
                "Description": {
                    "S": "Are you looking for a strong companion for raids, someone to throw lightning during a pillage, or just a cuddly buddy who can light a campfire from 200 meters? Look no further than Rujin, a troll mage just coming into his teenage years. Rujin is a loyal companion who loves adventure, camping, and long walks through burning villages. He is great with kids and makes a wonderful guard-troll, especially if you have a couple bridges on your property. Rujin has a bit of a soft spot for gold, so you’ll need to keep yours well hidden from him. Since he does keep a hoard on our property, we’re waiving the adoption fee!"
                },
                "Age": {"N": "221"},
                "GoodEvil": {"S": "Evil"},
                "LawChaos": {"S": "Chaotic"},
                "ThumbImageUri": {"S": "https://www.mythicalmysfits.com/images/troll_thumb.png"},
                "ProfileImageUri": {"S": "https://www.mythicalmysfits.com/images/troll_hover.png"},
                "Likes": {"N": "0"},
                "Adopted": {"BOOL": False},
            }
        }
    },
]
table_name = os.environ["mysfitsTable"]


# source adapted from https://github.com/aws-samples/aws-modern-application-workshop/blob/python-cdk/module-3/data/populate-dynamodb.json
def insertMysfits(event, context):
    response = client.batch_write_item(
        RequestItems={
            table_name: init_data,
        }
    )
    print(response)
