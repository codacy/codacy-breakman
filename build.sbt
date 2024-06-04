name := "codacy-brakeman"

scalaVersion := "2.13.13"

libraryDependencies ++= Seq("com.typesafe.play" %% "play-json" % "2.10.5",
                            "com.codacy" %% "codacy-engine-scala-seed" % "6.1.2")

enablePlugins(JavaAppPackaging)
