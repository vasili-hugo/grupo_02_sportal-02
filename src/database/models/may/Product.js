module.exports = (sequelize, dataTypes) => {
  let alias = 'Product';
  let cols = {
    id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      primaryKey: true,
      autoIncrement: true,
      autoNull: false
    },
    code: {
      type: dataTypes.STRING(100),
      autoNull: false
    },
    brand_id: {
        type: dataTypes.BIGINT(10).UNSIGNED,
        allowNull: false
    },
    heading_id: {
        type: dataTypes.BIGINT(10).UNSIGNED,
        allowNull: false
    },
    model: {
        type: dataTypes.STRING(100),
        allowNull: false
    },
    family_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      allowNull: false
    },
    desc: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    price: {
      type: dataTypes.DECIMAL(9,2),
      allowNull: false,
      default: 0.00
    },
    age_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      allowNull: false
    },
    sex_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      allowNull: false
    },
    color_id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      allowNull: false
    },
    image: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    left_image: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    right_image: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    upper_image: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    lower_image: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    inactive: {
      type: dataTypes.BOOLEAN,
      allowNull: false
    },
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "products",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Product = sequelize.define(alias, cols, config); 

  Product.associate = function (models) {
    Product.belongsTo(models.Brand, {
      as: "brands",
      foreignKey: 'brand_id'
    });

    Product.belongsTo(models.Heading, {
      as: "headings",
      foreignKey: 'heading_id'
    });

    Product.belongsTo(models.Family, {
      as: "families",
      foreignKey: 'family_id'
    });

    Product.belongsTo(models.Age, {
      as: "ages",
      foreignKey: 'age_id'
    });

    Product.belongsTo(models.Sex, {
      as: "sex",
      foreignKey: 'sex_id'
    });

    Product.belongsTo(models.Color, {
      as: "colors",
      foreignKey: 'color_id'
    });

    Product.belongsToMany(models.User, {
      as: "Product_ShoppingCart",
      through: 'shopping_cart',
      foreignKey: 'product_id',
      otherKey: 'user_id',
      timestamps: true
    });
  }
  return Product;
}