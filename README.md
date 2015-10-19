[![Codacy Badge](https://api.codacy.com/project/badge/25f3667db77c4c638be01d9f7453dec8)](https://www.codacy.com/app/Codacy/codacy-brakeman)
[![Build Status](https://circleci.com/gh/codacy/codacy-brakeman.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/codacy/codacy-brakeman)

create the docker: sbt docker:publishLocal

the docker is supposed to be run with the following command:

```
docker run -it -v $srcDir:/src  <DOCKER_NAME>:<DOCKER_VERSION>
```

and $srcDir must contain a valid .codacy.json configuration

## Docs

[Docker Docs](http://docs.codacy.com/v1.0/docs/tool-developer-guide)

[Scala Docker Template Docs](http://docs.codacy.com/v1.0/docs/tool-developer-guide-scala)

## Test

Follow the instructions at [codacy-plugins-test](https://github.com/codacy/codacy-plugins-test/blob/master/README.md#test-definition)
