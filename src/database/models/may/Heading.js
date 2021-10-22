module.exports = (sequelize, dataTypes) => {
  let alias = 'Heading';
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
    tableName: "headings",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Heading = sequelize.define(alias, cols, config); 

  Heading.associate = function (models) {
    Heading.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'heading_id'
    });
  }
  return Heading;
}