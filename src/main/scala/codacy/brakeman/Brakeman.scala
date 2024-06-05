package codacy.brakeman

import com.codacy.plugins.api.results.{Pattern, Result, Tool}
import com.codacy.plugins.api.{ErrorMessage, Options, Source}
import com.codacy.tools.scala.seed.utils.ToolHelper._
import com.codacy.tools.scala.seed.utils.{CommandResult, CommandRunner}
import play.api.libs.functional.syntax._
import play.api.libs.json._

import scala.util.{Failure, Success, Try}

case class WarnResult(warningCode: Int, message: String, file: String, line: JsValue)

object WarnResult {
  implicit val warnReads: Reads[WarnResult] = (
    (__ \ "warning_code")
      .read[Int]
      .and((__ \ "message").read[String])
      .and((__ \ "file").read[String])
      .and((__ \ "line").read[JsValue])
    )(WarnResult.apply _)
}

object Brakeman extends Tool {

  private val skipLibsKey = Options.Key("skip_libs")

  private val noBranchingKey = Options.Key("no_branching")

  private def checkNonRailsProject(resultFromTool: CommandResult): Boolean = {
    resultFromTool.stderr.exists(_.contains("Please supply the path to a Rails application"))
  }

  def apply(source: Source.Directory,
            configuration: Option[List[Pattern.Definition]],
            files: Option[Set[Source.File]],
            options: Map[Options.Key, Options.Value])(implicit specification: Tool.Specification): Try[List[Result]] = {

    def isEnabled(result: Result) = {
      result match {
        case res: Result.Issue =>
          configuration.forall(_.exists {
            _.patternId == res.patternId
          }) &&
            files.forall(_.exists(_.toString.endsWith(res.file.path)))

        case res: Result.FileError =>
          files.forall(_.exists(_.toString.endsWith(res.file.path)))

        case _ => true
      }
    }

    val skipLibs = options.get(skipLibsKey).fold(false) { value =>
      Option(value: JsValue)
        .collect {
          case JsBoolean(enabled) => enabled
          case _ => false
        }
        .getOrElse(false)
    }

    val noBranching = options.get(noBranchingKey).fold(false) { value =>
      Option(value: JsValue)
        .collect {
          case JsBoolean(enabled) => enabled
          case _ => false
        }
        .getOrElse(false)
    }

    val command = getCommandFor(source, configuration, files, skipLibs, noBranching)

    CommandRunner.exec(command) match {
      case Right(resultFromTool) =>
        if (checkNonRailsProject(resultFromTool)) {
          Try(List.empty)
        } else {
          val results = parseToolResult(resultFromTool.stdout, source)
          results.map(_.filter(isEnabled))
        }
      case Left(ex) => Failure(ex)
    }
  }

  private def warningToPatternId(warningCode: Int): String = {
    warningCode match {
      // This was automatically generated. Do not change.
      case 0 => "SQL"
      case 1 => "SQL"
      case 2 => "CrossSiteScripting"
      case 3 => "LinkTo"
      case 4 => "LinkToHref"
      case 5 => "CrossSiteScripting"
      case 7 => "ForgerySetting"
      case 8 => "SkipBeforeFilter"
      case 9 => "BasicAuth"
      case 10 => "SkipBeforeFilter"
      case 11 => "DefaultRoutes"
      case 12 => "DefaultRoutes"
      case 13 => "Evaluation"
      case 14 => "Execute"
      case 15 => "Render"
      case 16 => "FileAccess"
      case 17 => "MassAssignment"
      case 18 => "Redirect"
      case 19 => "ModelAttributes"
      case 20 => "ModelAttributes"
      case 21 => "SafeBufferManipulation"
      case 22 => "SelectVulnerability"
      case 23 => "Send"
      case 24 => "UnsafeReflection"
      case 25 => "Deserialize"
      case 26 => "SessionSettings"
      case 27 => "SessionSettings"
      case 28 => "TranslateBug"
      case 29 => "SessionSettings"
      case 30 => "ValidationRegex"
      case 31 => "NestedAttributes"
      case 32 => "MailTo"
      case 33 => "ForgerySetting"
      case 34 => "FilterSkipping"
      case 35 => "QuoteTableName"
      case 36 => "StripTags"
      case 37 => "ResponseSplitting"
      case 42 => "DigestDoS"
      case 43 => "SelectTag"
      case 44 => "SingleQuotes"
      case 45 => "StripTags"
      case 48 => "YAMLParsing"
      case 49 => "JSONParsing"
      case 50 => "ModelSerialize"
      case 51 => "ModelAttributes"
      case 52 => "JSONParsing"
      case 53 => "ContentTag"
      case 54 => "WithoutProtection"
      case 55 => "SymbolDoSCVE"
      case 56 => "SanitizeMethods"
      case 57 => "JRubyXML"
      case 58 => "SanitizeMethods"
      case 59 => "SymbolDoS"
      case 60 => "ModelAttrAccessible"
      case 61 => "DetailedExceptions"
      case 62 => "DetailedExceptions"
      case 63 => "I18nXSS"
      case 64 => "HeaderDoS"
      case 67 => "SimpleFormat"
      case 68 => "SimpleFormat"
      case 70 => "MassAssignment"
      case 71 => "SSLVerify"
      case 72 => "SQLCVEs"
      case 73 => "NumberToCurrency"
      case 74 => "NumberToCurrency"
      case 75 => "RenderDoS"
      case 76 => "RegexDoS"
      case 77 => "DefaultRoutes"
      case 80 => "CreateWith"
      case 81 => "CreateWith"
      case 82 => "UnscopedFind"
      case 83 => "EscapeFunction"
      case 84 => "RenderInline"
      case 85 => "FileDisclosure"
      case 86 => "ForgerySetting"
      case 87 => "JSONEncoding"
      case 88 => "XMLDoS"
      case 89 => "SessionManipulation"
      case 90 => "WeakHash"
      case 91 => "WeakHash"
      case 92 => "DynamicFinders"
      case 93 => "BasicAuthTimingAttack"
      case 94 => "MimeTypeDoS"
      case 95 => "NestedAttributesBypass"
      case 98 => "StripTags"
      case 99 => "Render"
      case 100 => "RouteDoS"
      case 101 => "Secrets"
      case 102 => "ContentTag"
      case 104 => "DivideByZero"
      case 105 => "PermitAttributes"
      case 106 => "SanitizeMethods"
      case _ => "UnknowError"
    }
  }

  private def warningToResult(warn: JsValue): Option[Result] = {

    //In our tests we have the pattern and the error type
    lazy val defaultLineWarning = 1

    warn.asOpt[WarnResult].map { res =>
      val source = Source.File(res.file)
      val resultMessage = Result.Message(res.message)
      val patternId = Pattern.Id(warningToPatternId(res.warningCode))
      val line = Source.Line(res.line match {
        case lineNumber: JsNumber => lineNumber.value.toInt
        case _ => defaultLineWarning
      })

      Result.Issue(source, resultMessage, patternId, line)
    }

  }

  private def stripPath(filename: String, path: String): String = {

    val FilenameRegex = s""".*$path/(.*)""".r

    filename match {
      case FilenameRegex(res) => res;
      case _ => filename
    }
  }

  private def errorToResult(err: JsValue, path: String): Option[Result] = {

    lazy val ErrorPattern = """(.+):\s*([0-9]+)\s*::(.+)""".r

    val errorString = (err \ "error").asOpt[String].getOrElse("")

    errorString match {
      case ErrorPattern(filename, line, msg) =>
        Some(Result.FileError(Source.File(stripPath(filename, path)), Some(ErrorMessage(s"On line $line: $msg"))))
      case _ => None
    }

  }

  private def parseToolResult(resultFromTool: List[String], path: Source.Directory): Try[List[Result]] = {

    val jsonParsed: Try[JsValue] = Try(Json.parse(resultFromTool.mkString))

    jsonParsed match {
      case Success(jsonResult) =>
        val errors = (jsonResult \ "errors").asOpt[JsArray].fold(Seq[JsValue]())(arr => arr.value.toSeq).toList
        val warnings = (jsonResult \ "warnings").asOpt[JsArray].fold(Seq[JsValue]())(arr => arr.value.toSeq).toList

        Success(warnings.flatMap(warningToResult) ++ errors.flatMap(err => errorToResult(err, path.toString)))

      case Failure(ex) => Failure(ex)
    }
  }

  private[this] def getCommandFor(path: Source.Directory,
                                  conf: Option[List[Pattern.Definition]],
                                  files: Option[Set[Source.File]],
                                  skipLibs: Boolean,
                                  noBranching: Boolean)(implicit spec: Tool.Specification): List[String] = {

    val patternsToTest = conf.withDefaultParameters
      .map { patterns =>
        val patternsIds = patterns.map(p => p.patternId.value)
        List("-t", patternsIds.mkString(","))
      }
      .getOrElse(List.empty)

    val skipLibsCmd = if (skipLibs) List("--skip-libs") else List.empty
    val noBranchingCmd = if (noBranching) List("--no-branching") else List.empty

    List("brakeman", "-f", "json") ++ skipLibsCmd ++ noBranchingCmd ++ patternsToTest ++ List(path.toString)
  }
}

case class BrakemanParserException(message: String) extends Exception(message)
