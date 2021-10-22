module.exports = (sequelize, dataTypes) => {
  let alias = 'Color';
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
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "colors",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Color = sequelize.define(alias, cols, config); 

  Color.associate = function (models) {
    Color.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'color_id'
    });
  }
  return Color;
}