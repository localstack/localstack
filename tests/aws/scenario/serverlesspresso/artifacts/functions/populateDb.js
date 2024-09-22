// Source adapted from: https://github.com/aws-samples/serverless-coffee-workshop/setup/initDB/initMenu.js
// modified from official sample to fit into a single file

const { DynamoDB } = require('@aws-sdk/client-dynamodb');

const documentClient = new DynamoDB({
  region: process.env.AWS_REGION || 'us-east-1'
})


const configTableName = process.env.configTable
const countingTableName = process.env.countingTable

const initCountingState = [
  {
    "PK": {
      "S": "orderID"
    },
    "IDvalue": {
      "N": "0"
    }
  }
];

const initMenuState = [
   {
  "PK": {
    "S": "menu"
  },
  "value": {
    "L": [
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_espresso-alternative"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Espresso"
          }
        }
      },
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_cappuccino-alternative"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Cappuccino"
          }
        }
      },
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_cafe-latte"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Latte"
          }
        }
      },
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_flat-white-alternative@2x"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Flat White"
          }
        }
      },
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_americano"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Americano"
          }
        }
      },
      {
        "M": {
          "available": {
            "BOOL": true
          },
          "icon": {
            "S": "barista-icons_americano"
          },
          "modifiers": {
            "L": []
          },
          "drink": {
            "S": "Coffee of the day"
          }
        }
      }
    ]
  }
},
    {
      "PK": {
        "S": "config"
      },
      "storeOpen": {
        "BOOL": true
      },
      "maxOrdersPerUser": {
        "N": "1"
      },
      "maxOrdersInQueue": {
        "N": "10"
      }
    }
];

const initMenu = async () => {
  try {
    // BatchWrite params template
    const params = {
      RequestItems: {
        [configTableName]: [],
        [countingTableName]: []
      }
    }

    // Load in d template
    initMenuState.map((d) => {
      console.log(d)
      params.RequestItems[configTableName].push ({
        PutRequest: {
          Item: {
            ...d
          }
        }
      })
    })

    initCountingState.map((d) => {
      console.log(d)
      params.RequestItems[countingTableName].push ({
        PutRequest: {
          Item: {
            ...d
          }
        }
      })
    })

    console.log('params',JSON.stringify(params,null,0))
    const result = await documentClient.batchWriteItem(params)
    console.log('initMenus result: ', result)
  } catch (err) {
    console.error('initMenus error: ', err)
  }
}

exports.handler = async function (event, context) {
  console.log('REQUEST RECEIVED:\n' + JSON.stringify(event))
  await initMenu()
  return "ok"
}
