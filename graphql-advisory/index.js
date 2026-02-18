const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');

const app = express();

// 1️⃣ Define Schema
const schema = buildSchema(`
  type Book {
    id: ID!
    title: String!
    author: String!
  }

  type Query {
    books: [Book]
    book(id: ID!): Book
  }

  type Mutation {
    addBook(title: String!, author: String!): Book
  }
`);

// 2️⃣ Dummy Data
let books = [
  { id: '1', title: 'Clean Code', author: 'Robert Martin' },
  { id: '2', title: 'Atomic Habits', author: 'James Clear' }
];

// 3️⃣ Resolvers
const root = {
  books: () => books,
  book: ({ id }) => books.find(book => book.id === id),
  addBook: ({ title, author }) => {
    const newBook = {
      id: String(books.length + 1),
      title,
      author
    };
    books.push(newBook);
    return newBook;
  }
};

// 4️⃣ Middleware
app.use('/graphql', graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true
}));

app.listen(4000, () => {
  console.log('Server running at http://localhost:4000/graphql');
});
