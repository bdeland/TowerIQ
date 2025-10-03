module.exports = {
  // ...your config
  reporters: [
    "default",
    [
      "jest-junit",
      { outputDirectory: "_reports/junit", outputName: "jest.xml" },
    ],
  ],
};
