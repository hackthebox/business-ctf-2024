const { GraphQLObjectType, GraphQLString, GraphQLID, GraphQLBoolean } = require('graphql');

const UserType = new GraphQLObjectType({
    name: 'User',
    fields: () => ({
      id: { type: GraphQLID },
      name: { type: GraphQLString },
      department: { type: GraphQLString },
      isPresent: { type: GraphQLBoolean }
    })
  });

module.exports = UserType