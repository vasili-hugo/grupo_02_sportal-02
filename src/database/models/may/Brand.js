module.exports = (sequelize, dataTypes) => {
  let alias = 'Brand';
  let cols = {
    id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      autoNull: false,
      primaryKey: true,
      autoIncrement: true
    },
    desc: {
      type: dataTypes.STRING(255),
      autoNull: false
    },
    icon: {
        type: dataTypes.STRING(255),
        allowNull: false
    },
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "brands",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Brand = sequelize.define(alias, cols, config); 

  Brand.associate = function (models) {
    Brand.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'brand_id'
    });
  }
  return Brand;
}