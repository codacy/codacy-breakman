require "bundler"
require "brakeman"
require "brakeman/scanner"
require "brakeman/report/report_codeclimate"
require "json"
require_relative 'SecuritySubcategory'

default_patterns = [
  "Deserialize",
  "YAMLParsing",
  "RenderDoS",
  "SessionSettings",
  "RenderInline",
  "SimpleFormat",
  "ResponseSplitting",
  "ContentTag",
  "EscapeFunction",
  "FileDisclosure",
  "MailTo",
  "CrossSiteScripting",
  "FileAccess",
  "FilterSkipping",
  "Redirect",
  "RegexDoS",
  "ForgerySetting",
  "DefaultRoutes",
  "SQL",
  "I18nXSS",
  "Execute",
  "JSONParsing",
  "MassAssignment",
  "SSLVerify",
  "SymbolDoS",
  "WithoutProtection",
  "DetailedExceptions",
  "HeaderDoS",
  "JRubyXML",
  "ModelAttrAccessible",
  "JSONEncoding",
  "QuoteTableName",
  "CreateWith",
  "BasicAuth",
  "LinkToHref",
  "Send",
  "LinkTo",
  "XMLDoS",
  "DigestDoS",
  "Evaluation",
  "ModelAttributes",
  "ModelSerialize",
  "NestedAttributes",
  "Render",
  "SQLCVEs",
  "SafeBufferManipulation",
  "SanitizeMethods",
  "SelectTag",
  "SelectVulnerability",
  "SingleQuotes",
  "SkipBeforeFilter",
  "StripTags",
  "SymbolDoSCVE",
  "TranslateBug",
  "UnsafeReflection",
  "UnscopedFind",
  "ValidationRegex"
]

checks = Brakeman::Checks.checks
remediations = YAML.load_file(Brakeman::Report::CodeClimate::REMEDIATION_POINTS_CONFIG_PATH)

brakeman_gem_path = Bundler.rubygems.find_name("brakeman").first.full_gem_path
directory = "#{brakeman_gem_path}/lib/brakeman/checks/*.rb"
mapping = Brakeman::WarningCodes::Codes.collect { |code, value|
  next if code == :csrf_protection_disabled ||
          code == :CVE_2012_2660 ||
          code == :CVE_2012_2661 ||
          code == :CVE_2012_2695 ||
          code == :CVE_2012_5664 ||
          code == :CVE_2013_0155 ||
          code == :CVE_2013_6417 ||
          code == :CVE_2014_3482 ||
          code == :CVE_2014_3483 ||
          code == :CVE_2015_7578 ||
          code == :CVE_2015_7580 ||
          code == :CVE_2016_6317 ||
          code == :CVE_2018_3741
  file = Dir[directory].find { |file| File.read(file).include?(":#{code},") } ||
         Dir[directory].find { |file| File.read(file).include?(code.to_s) }
  check = checks
    .sort_by { |check| -check.name.size }
    .find { |check| File.basename(file, ".*").tr("_", "").include?(check.name.downcase) }
  {
    :code => code.to_s,
    :patternId => check.name.sub("Check", ""),
    :value => value,
    :remediation => [(remediations[code.to_s] || 100000) * 20 / 100000, 4 * 60].min,
  }
}.compact.sort_by { |pattern| pattern[:value] }

def pattern_subcategory(name)  
  SecuritySubcategory::Mapping.select { |subcategory|
    SecuritySubcategory::Mapping[subcategory].include?(name)
  }.keys.first
end

patterns_with_category = checks.map { |check|
  patternId = check.name.sub("Check", "")
  {
    :patternId => patternId,
    :level => "Warning",
    :category => "Security",
    :subcategory => pattern_subcategory(patternId),
    :enabled => default_patterns.include?(patternId),
  }.delete_if { |_, value| value.nil? }
}

patterns = {
  :name => "brakeman",
  :version => Brakeman::Version,
  :patterns => patterns_with_category.sort_by { |pattern| pattern[:patternId] },
}

File.open("docs/patterns.json", "w") do |f|
  f.puts JSON.pretty_generate(patterns)
end

description = checks.map { |check|
  {
    :patternId => check.name.sub("Check", ""),
    :title => check.description,
    :description => check.description,
    :timeToFix => 20,
  }
}.sort_by { |pattern| pattern[:patternId] }

File.open("docs/description/description.json", "w") do |f|
  f.puts JSON.pretty_generate(description)
end

puts mapping.map { |pattern| "      case #{pattern[:value]} => \"#{pattern[:patternId]}\"" }
