module.exports = {
  roots: ['<rootDir>/lib'],
  moduleDirectories: ['<rootDir>'],
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  silent: false,
  testMatch: ['**/?(*.)+(spec|test).+(ts|tsx|js)'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
    '^.+\\.js$': 'babel-jest',
  },
  transformIgnorePatterns: ['node_modules/(?!(sinon)/)'],
  collectCoverage: true,
};
