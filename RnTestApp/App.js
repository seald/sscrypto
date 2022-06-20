/**
 * React Native App to run tests
 */
import React, {useState} from 'react';
import {StyleSheet, Text, View, Button, Switch, Platform} from 'react-native';
import 'deca/build/lib/bdd-global.js';
import '../tests/test-rn.spec.bundle.js';

const printResult_ = (result, depth = 0) => {
  if (result.success) {
    console.log(`${'  '.repeat(depth)}✅  ${result.name}`);
  } else {
    console.log(`${'  '.repeat(depth)}❌  ${result.name}`);
  }
  for (const test of result.tests) {
    if (!test.error) {
      console.log(`${'  '.repeat(depth + 1)}✅  ${test.name}`);
    } else {
      console.log(`${'  '.repeat(depth + 1)}❌  ${test.name} (error)`);
      console.error(test.error);
      if (
        Object.prototype.hasOwnProperty.call(test.error, 'actual') &&
        Object.prototype.hasOwnProperty.call(test.error, 'expected')
      ) {
        const {actual, expected} = test.error;
        console.error('Actual: ' + actual);
        console.error('Expected: ' + expected);
      }
    }
  }
  for (const subSuite of result.subSuites) {
    printResult_(subSuite, depth + 1);
  }
};

const printResult = result => {
  if (result.name === '') {
    if (result.tests.length === 0) {
      for (const subSuite of result.subSuites) {
        printResult_(subSuite);
      }
    } else {
      printResult_({
        ...result,
        name: 'Global',
      });
    }
  } else {
    printResult_(result);
  }

  console.log(`✅  ${result.nPassing} passing`);
  if (result.nFailed > 0) {
    console.log(`❌  ${result.nFailed} failed`);
  }
};

export default function App() {
  const [hasStarted, setHasStarted] = useState(false);
  const [hasFinished, setHasFinished] = useState(false);

  const [isTestSwitchEnabled, setIsTestSwitchEnabled] = useState(false);
  const toggleTestSwitch = () =>
    setIsTestSwitchEnabled(previousState => !previousState);
  console.log('IS HERMES:', Boolean(global.HermesInternal));
  console.log('PLATFORM:', Platform);

  const doTest = async () => {
    if (hasStarted) {
      return;
    }
    console.log('Running doTest');
    setHasStarted(true);
    const result = await global.runTests();
    console.log(result);
    // log results
    printResult(result);
    setHasFinished(true);
  };
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const reset = async () => {
    setHasStarted(false);
    setHasFinished(false);
  };

  return (
    <View style={styles.container}>
      {/* <Button onPress={reset} title="RESET" /> */}
      <Switch
        trackColor={{false: '#767577', true: '#81b0ff'}}
        thumbColor={isTestSwitchEnabled ? '#f5dd4b' : '#f4f3f4'}
        ios_backgroundColor="#3e3e3e"
        onValueChange={toggleTestSwitch}
        value={isTestSwitchEnabled}
      />
      {isTestSwitchEnabled ? (
        <Text>Test switch enabled</Text>
      ) : (
        <Text>Test switch disabled</Text>
      )}
      {hasFinished ? (
        <Text>Finished!</Text>
      ) : hasStarted ? (
        <Button disabled={true} title="Running Tests..." />
      ) : (
        <Button onPress={doTest} title="Start Tests" />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  button: {
    padding: 30,
  },
});
