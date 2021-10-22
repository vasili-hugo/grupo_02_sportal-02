module.exports = (sequelize, dataTypes) => {
  let alias = 'ShoppingCart';
  let cols = {
    id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      autoNull: false,
      primaryKey: true,
      autoIncrement: true
    },
    product_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      autoNull: false,
    },
    user_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      autoNull: false,
    },
    quantity: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      default: 0
    },
    price: {
      type: dataTypes.DECIMAL(9,2),
      default: 0.00
    },
    billed: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      default: 0
    },
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "shopping_cart",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const ShoppingCart = sequelize.define(alias, cols, config); 

  ShoppingCart.associate = function (models) {
    ShoppingCart.belongsToMany(models.Product, {
      as: "ShoppingCart_Product",
      through: "products",
      foreignKey: 'product_id',
      otherKey: "id",
      timestamps: true
    });
  }
  
  ShoppingCart.associate = function (models) {
    ShoppingCart.belongsToMany(models.User, {
      as: "ShoppingCart_User",
      through: "users",
      foreignKey: 'user_id',
      otherKey: "id",
      timestamps: true
    });
  }
  return ShoppingCart;
}
