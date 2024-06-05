name := "codacy-brakeman"

scalaVersion := "2.13.13"

libraryDependencies ++= Seq("org.playframework" %% "play-json" % "3.0.3",
                            "com.codacy" %% "codacy-engine-scala-seed" % "5.0.1")

enablePlugins(JavaAppPackaging)
