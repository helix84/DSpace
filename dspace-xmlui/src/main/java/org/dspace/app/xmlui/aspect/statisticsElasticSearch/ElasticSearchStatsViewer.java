/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.xmlui.aspect.statisticsElasticSearch;

import org.apache.cocoon.environment.ObjectModelHelper;
import org.apache.cocoon.environment.Request;
import org.apache.log4j.Logger;
import org.dspace.app.xmlui.cocoon.AbstractDSpaceTransformer;
import org.dspace.app.xmlui.utils.HandleUtil;
import org.dspace.app.xmlui.wing.Message;
import org.dspace.app.xmlui.wing.WingException;
import org.dspace.app.xmlui.wing.element.*;
import org.dspace.content.*;
import org.dspace.content.Item;
import org.dspace.core.Constants;
import org.dspace.core.ConfigurationManager;
import org.dspace.statistics.DataTermsFacet;
import org.dspace.statistics.ElasticSearchLogger;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.SearchType;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.action.search.SearchRequestBuilder;
import org.elasticsearch.index.query.*;
import org.elasticsearch.search.facet.AbstractFacetBuilder;
import org.elasticsearch.search.facet.FacetBuilders;
import org.elasticsearch.search.facet.datehistogram.DateHistogramFacet;
import org.elasticsearch.search.facet.terms.TermsFacet;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * Usage Statistics viewer, powered by Elastic Search.
 * Allows for the user to dig deeper into the statistics for topDownloads, topCountries, etc.
 * @author Peter Dietz (pdietz84@gmail.com)
 */
public class ElasticSearchStatsViewer extends AbstractDSpaceTransformer {
    private static Logger log = Logger.getLogger(ElasticSearchStatsViewer.class);
    
    public static final String elasticStatisticsPath = "stats";

    private static SimpleDateFormat monthAndYearFormat = new SimpleDateFormat("MMMMM yyyy");
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

    private static Client client;
    private static Division division;
    private static DSpaceObject dso;
    private static Date dateStart;
    private static Date dateEnd;

    protected static TermFilterBuilder justOriginals = FilterBuilders.termFilter("bundleName", "ORIGINAL");

    protected static AbstractFacetBuilder facetTopCountries = FacetBuilders.termsFacet("top_countries").field("country.untouched").size(150)
            .facetFilter(FilterBuilders.andFilter(
                justOriginals,
                FilterBuilders.notFilter(FilterBuilders.termFilter("country.untouched", "")))
            );

    protected static AbstractFacetBuilder facetMonthlyDownloads = FacetBuilders.dateHistogramFacet("monthly_downloads").field("time").interval("month")
            .facetFilter(FilterBuilders.andFilter(
                FilterBuilders.termFilter("type", "BITSTREAM"),
                justOriginals
            ));
    
    protected static AbstractFacetBuilder facetTopBitstreamsAllTime = FacetBuilders.termsFacet("top_bitstreams_alltime").field("id")
            .facetFilter(FilterBuilders.andFilter(
                    FilterBuilders.termFilter("type", "BITSTREAM"),
                    justOriginals
            ));
    
    protected static AbstractFacetBuilder facetTopUSCities = FacetBuilders.termsFacet("top_US_cities").field("city.untouched").size(50)
            .facetFilter(FilterBuilders.andFilter(
                FilterBuilders.termFilter("countryCode", "US"),
                justOriginals,
                FilterBuilders.notFilter(FilterBuilders.termFilter("city.untouched", ""))
            ));
    
    protected static AbstractFacetBuilder facetTopUniqueIP = FacetBuilders.termsFacet("top_unique_ips").field("ip");
    
    protected static AbstractFacetBuilder facetTopTypes = FacetBuilders.termsFacet("top_types").field("type");

    /** Language strings */
    private static final Message T_dspace_home = message("xmlui.general.dspace_home");

    private static final Message T_reportTitle = message("xmlui.statistics.ElasticSearchStatsViewer.reportTitle");
    private static final Message T_statistics_view = message("xmlui.statistics.Navigation.elasticsearch.view");
    public static final Message T_showDataRange = message("xmlui.statistics.ElasticSearchStatsViewer.showDateRange");
    public static final Message T_lastFiveYears = message("xmlui.statistics.ElasticSearchStatsViewer.dateRangeLastFiveYears");
    public static final Message T_fromDateToDate = message("xmlui.statistics.ElasticSearchStatsViewer.fromDateToDate");
    public static final Message T_startingFrom = message("xmlui.statistics.ElasticSearchStatsViewer.startingFrom");
    public static final Message T_endingWith = message("xmlui.statistics.ElasticSearchStatsViewer.endingWith");
    public static final Message T_allData = message("xmlui.statistics.ElasticSearchStatsViewer.allData");
    public static final Message T_topDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.topDownloads");
    public static final Message T_topDownloadsAllTime = message("xmlui.statistics.ElasticSearchStatsViewer.topDownloadsAllTime");
    public static final Message T_noDataAvailable = message("xmlui.statistics.ElasticSearchStatsViewer.noDataAvailable");
    public static final Message T_count = message("xmlui.statistics.ElasticSearchStatsViewer.count");
    public static final Message T_dateHeader = message("xmlui.statistics.ElasticSearchStatsViewer.dateHeader");

    public static final Message T_metadataTitle = message("xmlui.statistics.ElasticSearchStatsViewer.metadata.title");
    public static final Message T_metadataCreator = message("xmlui.statistics.ElasticSearchStatsViewer.metadata.creator");
    public static final Message T_metadataPublisher = message("xmlui.statistics.ElasticSearchStatsViewer.metadata.publisher");
    public static final Message T_metadataDate = message("xmlui.statistics.ElasticSearchStatsViewer.metadata.date");

    public static final Message T_viewsPerType = message("xmlui.statistics.ElasticSearchStatsViewer.viewsPerType");
    public static final Message T_numberFileDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.numberOfFileDownloads");
    public static final Message T_fileDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.fileDownloads");
    public static final Message T_totalDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.totalDownloads");
    public static final Message T_headerCountry = message("xmlui.statistics.ElasticSearchStatsViewer.headerCountry");
    public static final Message T_headerCity = message("xmlui.statistics.ElasticSearchStatsViewer.headerCity");
    public static final Message T_headerDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.headerDownloads");
    public static final Message T_forMoreInformation = message("xmlui.statistics.ElasticSearchStatsViewer.forMoreInformation");
    public static final Message T_numberOfDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.numberOfDownloads");
    public static final Message T_countriesWithDownloads = message("xmlui.statistics.ElasticSearchStatsViewer.countriesWithDownloads");

    public void addPageMeta(PageMeta pageMeta) throws WingException, SQLException {
        DSpaceObject dso = HandleUtil.obtainHandle(objectModel);

        pageMeta.addMetadata("title").addContent(T_reportTitle.parameterize(dso.getName()));

        pageMeta.addTrailLink(contextPath + "/",T_dspace_home);
        HandleUtil.buildHandleTrail(dso,pageMeta,contextPath, true);
        pageMeta.addTrail().addContent(T_statistics_view);
    }

    public ElasticSearchStatsViewer() {

    }

    public ElasticSearchStatsViewer(DSpaceObject dso, Date dateStart, Date dateEnd) {
        this.dso = dso;
        this.dateStart = dateStart;
        this.dateEnd = dateEnd;
        client = ElasticSearchLogger.getInstance().getClient();
    }
    
    public void addBody(Body body) throws WingException, SQLException {
        try {
            //Try to find our dspace object
            dso = HandleUtil.obtainHandle(objectModel);
            client = ElasticSearchLogger.getInstance().getClient();

            division = body.addDivision("elastic-stats");
            division.setHead(T_reportTitle.parameterize(dso.getName()));
            division.addHidden("containerName").setValue(dso.getName());

            division.addHidden("baseURLStats").setValue(contextPath + "/handle/" + dso.getHandle() + "/" + elasticStatisticsPath);
            Request request = ObjectModelHelper.getRequest(objectModel);
            String[] requestURIElements = request.getRequestURI().split("/");

            //Add Hidden i18n keys for Javascipt to use translated strings
            division.addHidden("i18nViewsDSOType").setValue(T_viewsPerType);
            division.addHidden("i18nNumberFileDownloads").setValue(T_numberFileDownloads);
            division.addHidden("i18nDate").setValue(T_dateHeader);
            division.addHidden("i18nFileDownloads").setValue(T_fileDownloads);
            division.addHidden("i18nTotalDownloads").setValue(T_totalDownloads);
            division.addHidden("i18nHeaderCity").setValue(T_headerCity);
            division.addHidden("i18nHeaderCountry").setValue(T_headerCountry);
            division.addHidden("i18nHeaderDownloads").setValue(T_headerDownloads);
            division.addHidden("i18nForMoreInformation").setValue(T_forMoreInformation);
            division.addHidden("i18nNumberOfDownloads").setValue(T_numberOfDownloads);
            division.addHidden("i18nCountriesWithDownloads").setValue(T_countriesWithDownloads);

            // If we are on the homepage of the statistics portal, then we just show the summary report
            // Otherwise we will show a form to let user enter more information for deeper detail.
            if(requestURIElements[requestURIElements.length-1].trim().equalsIgnoreCase(elasticStatisticsPath)) {
                //Homepage will show the last 5 years worth of Data, and no form generator.
                Calendar cal = Calendar.getInstance();
                dateEnd = cal.getTime();

                int years = ConfigurationManager.getIntProperty("elastic-search-statistics", "recent.years", 5);

                //Roll back to Jan 1 0:00.000 five years ago.
                cal.roll(Calendar.YEAR, -years);
                cal.set(Calendar.MONTH, 0);
                cal.set(Calendar.DAY_OF_MONTH, 1);
                cal.set(Calendar.HOUR_OF_DAY,0);
                cal.set(Calendar.MINUTE, 0);
                cal.set(Calendar.SECOND, 0);
                cal.set(Calendar.MILLISECOND, 0);
                dateStart = cal.getTime();

                division.addHidden("reportDepth").setValue("summary");

                Para divisionPara = division.addPara();
                divisionPara.addContent(T_showDataRange);
                divisionPara.addContent(T_lastFiveYears.parameterize(years));

                String dateRange = "Last " + years + " Years";
                division.addHidden("timeRangeString").setValue("Data Range: " + dateRange);
                
                if(dateStart != null) {
                    division.addHidden("dateStart").setValue(dateFormat.format(dateStart));
                }
                if(dateEnd != null) {
                    division.addHidden("dateEnd").setValue(dateFormat.format(dateEnd));
                }

                showAllReports();
                
            } else {
                //Other pages will show a form to choose which date range.
                ReportGenerator reportGenerator = new ReportGenerator();
                reportGenerator.addReportGeneratorForm(division, request);
                
                dateStart = reportGenerator.getDateStart();
                dateEnd = reportGenerator.getDateEnd();

                String requestedReport = requestURIElements[requestURIElements.length-1];
                log.info("Requested report is: "+ requestedReport);
                division.addHidden("reportDepth").setValue("detail");
                
                Message dateRange = null;
                if(dateStart != null && dateEnd != null) {
                    dateRange = T_fromDateToDate.parameterize(dateFormat.format(dateStart), dateFormat.format(dateEnd));
                } else if (dateStart != null && dateEnd == null) {
                    dateRange = T_startingFrom.parameterize(dateFormat.format(dateStart));
                } else if(dateStart == null && dateEnd != null) {
                    dateRange = T_endingWith.parameterize(dateFormat.format(dateEnd));
                } else if(dateStart == null && dateEnd == null) {
                    dateRange = T_allData;
                }

                Para dataRangePara = division.addPara();
                dataRangePara.addContent(T_showDataRange);
                dataRangePara.addContent(dateRange);

                division.addHidden("timeRangeString").setValue(dateRange);
                if(dateStart != null) {
                    division.addHidden("dateStart").setValue(dateFormat.format(dateStart));
                }
                if(dateEnd != null) {
                    division.addHidden("dateEnd").setValue(dateFormat.format(dateEnd));
                }


                division.addHidden("reportName").setValue(requestedReport);

                if(requestedReport.equalsIgnoreCase("topCountries"))
                {
                    SearchRequestBuilder requestBuilder = facetedQueryBuilder(facetTopCountries, facetTopUSCities);
                    searchResponseToDRI(requestBuilder);
                }
                else if(requestedReport.equalsIgnoreCase("fileDownloads"))
                {
                    SearchRequestBuilder requestBuilder = facetedQueryBuilder(facetMonthlyDownloads);
                    searchResponseToDRI(requestBuilder);
                }
                else if(requestedReport.equalsIgnoreCase("topDownloads"))
                {
                    SearchRequestBuilder requestBuilder = facetedQueryBuilder(facetTopBitstreamsAllTime, facetTopBitstreamsLastMonth());
                    SearchResponse resp = searchResponseToDRI(requestBuilder);

                    TermsFacet bitstreamsAllTimeFacet = resp.getFacets().facet(TermsFacet.class, "top_bitstreams_alltime");
                    addTermFacetToTable(bitstreamsAllTimeFacet, division, "Bitstream", T_topDownloadsAllTime);

                    TermsFacet bitstreamsFacet = resp.getFacets().facet(TermsFacet.class, "top_bitstreams_lastmonth");
                    addTermFacetToTable(bitstreamsFacet, division, "Bitstream", T_topDownloads.parameterize(getLastMonthString()));
                }
            }

        } finally {
            //client.close();
        }
    }
    
    public void showAllReports() throws WingException, SQLException{
        List<AbstractFacetBuilder> summaryFacets = new ArrayList<AbstractFacetBuilder>();
        summaryFacets.add(facetTopTypes);
        summaryFacets.add(facetTopUniqueIP);
        summaryFacets.add(facetTopCountries);
        summaryFacets.add(facetTopUSCities);
        summaryFacets.add(facetTopBitstreamsLastMonth());
        summaryFacets.add(facetTopBitstreamsAllTime);
        summaryFacets.add(facetMonthlyDownloads);

        SearchRequestBuilder requestBuilder = facetedQueryBuilder(summaryFacets);
        SearchResponse resp = searchResponseToDRI(requestBuilder);

                // Top Downloads to Owning Object
        TermsFacet bitstreamsFacet = resp.getFacets().facet(TermsFacet.class, "top_bitstreams_lastmonth");
        addTermFacetToTable(bitstreamsFacet, division, "Bitstream", T_topDownloads.parameterize(getLastMonthString()));

        // Convert Elastic Search data to a common DataTermsFacet object, and stuff in DRI/HTML of page.
        TermsFacet topBitstreamsFacet = resp.getFacets().facet(TermsFacet.class, "top_bitstreams_lastmonth");
        List<? extends TermsFacet.Entry> termsFacetEntries = topBitstreamsFacet.getEntries();
        DataTermsFacet termsFacet = new DataTermsFacet();
        for(TermsFacet.Entry entry : termsFacetEntries) {
            termsFacet.addTermFacet(new DataTermsFacet.TermsFacet(entry.getTerm(), entry.getCount()));
        }
        division.addHidden("jsonTopDownloads").setValue(termsFacet.toJson());
    }
    
    public AbstractFacetBuilder facetTopBitstreamsLastMonth() {
        Calendar calendar = Calendar.getInstance();

        // Show Previous Whole Month
        calendar.add(Calendar.MONTH, -1);

        calendar.set(Calendar.DAY_OF_MONTH, calendar.getActualMinimum(Calendar.DAY_OF_MONTH));
        String lowerBound = dateFormat.format(calendar.getTime());

        calendar.set(Calendar.DAY_OF_MONTH, calendar.getActualMaximum(Calendar.DAY_OF_MONTH));
        String upperBound = dateFormat.format(calendar.getTime());

        log.info("Lower:"+lowerBound+" -- Upper:"+upperBound);
        
        return FacetBuilders.termsFacet("top_bitstreams_lastmonth").field("id")
                .facetFilter(FilterBuilders.andFilter(
                        FilterBuilders.termFilter("type", "BITSTREAM"),
                        justOriginals,
                        FilterBuilders.rangeFilter("time").from(lowerBound).to(upperBound)
                ));
    }
    
    public String getLastMonthString() {
        Calendar calendar = Calendar.getInstance();
        // Show Previous Whole Month
        calendar.add(Calendar.MONTH, -1);

        calendar.set(Calendar.DAY_OF_MONTH, calendar.getActualMinimum(Calendar.DAY_OF_MONTH));
        return monthAndYearFormat.format(calendar.getTime());
    }
    
    public SearchRequestBuilder facetedQueryBuilder(AbstractFacetBuilder facet) throws WingException{
        List<AbstractFacetBuilder> facetList = new ArrayList<AbstractFacetBuilder>();
        facetList.add(facet);
        return facetedQueryBuilder(facetList);
    }

    public SearchRequestBuilder facetedQueryBuilder(AbstractFacetBuilder... facets) throws WingException {
        List<AbstractFacetBuilder> facetList = new ArrayList<AbstractFacetBuilder>();

        for(AbstractFacetBuilder facet : facets) {
            facetList.add(facet);
        }

        return facetedQueryBuilder(facetList);
    }
    
    public SearchRequestBuilder facetedQueryBuilder(List<AbstractFacetBuilder> facetList) {
        TermQueryBuilder termQuery = QueryBuilders.termQuery(getOwningText(dso), dso.getID());
        FilterBuilder rangeFilter = FilterBuilders.rangeFilter("time").from(dateStart).to(dateEnd);
        FilteredQueryBuilder filteredQueryBuilder = QueryBuilders.filteredQuery(termQuery, rangeFilter);

        SearchRequestBuilder searchRequestBuilder = client.prepareSearch(ElasticSearchLogger.getInstance().indexName)
                .setSearchType(SearchType.DFS_QUERY_THEN_FETCH)
                .setQuery(filteredQueryBuilder)
                .setSize(0);

        for(AbstractFacetBuilder facet : facetList) {
            searchRequestBuilder.addFacet(facet);
        }

        return searchRequestBuilder;
    }

    public SearchResponse searchResponseToDRI(SearchRequestBuilder searchRequestBuilder) throws WingException{
        division.addHidden("request").setValue(searchRequestBuilder.toString());

        SearchResponse resp = searchRequestBuilder.execute().actionGet();

        if(resp == null) {
            log.info("Elastic Search is down for searching.");
            division.addPara("Elastic Search seems to be down :(");
            return null;
        }

        division.addHidden("response").setValue(resp.toString());
        division.addDivision("chart_div");

        return resp;
    }

    private void addTermFacetToTable(TermsFacet termsFacet, Division division, String termName, Message tableHeader) throws WingException, SQLException {
        List<? extends TermsFacet.Entry> termsFacetEntries = termsFacet.getEntries();

        if(termName.equalsIgnoreCase("country")) {
            division.addDivision("chart_div_map");
        }

        Table facetTable = division.addTable("facet-"+termName, termsFacetEntries.size()+1, 10);
        facetTable.setHead(tableHeader);

        Row facetTableHeaderRow = facetTable.addRow(Row.ROLE_HEADER);
        if(termName.equalsIgnoreCase("bitstream")) {
            facetTableHeaderRow.addCellContent(T_metadataTitle);
            facetTableHeaderRow.addCellContent(T_metadataCreator);
            facetTableHeaderRow.addCellContent(T_metadataPublisher);
            facetTableHeaderRow.addCellContent(T_metadataDate);
        } else {
            facetTableHeaderRow.addCell().addContent(termName);
        }

        facetTableHeaderRow.addCell().addContent(T_count);

        if(termsFacetEntries.size() == 0) {
            facetTable.addRow().addCell().addContent(T_noDataAvailable);
            return;
        }

        for(TermsFacet.Entry facetEntry : termsFacetEntries) {
            Row row = facetTable.addRow();

            if(termName.equalsIgnoreCase("bitstream")) {
                Bitstream bitstream = Bitstream.find(context, Integer.parseInt(facetEntry.getTerm()));
                Item item = (Item) bitstream.getParentObject();
                row.addCell().addXref(contextPath + "/handle/" + item.getHandle(), item.getName());
                row.addCellContent(getFirstMetadataValue(item, "dc.creator"));
                row.addCellContent(getFirstMetadataValue(item, "dc.publisher"));
                row.addCellContent(getFirstMetadataValue(item, "dc.date.issued"));
            } else if(termName.equalsIgnoreCase("country")) {
                //TODO use users/OS locale to get country name
                row.addCell("country", Cell.ROLE_DATA,"country").addContent(new Locale("en", facetEntry.getTerm()).getDisplayCountry());
            } else {
                row.addCell().addContent(facetEntry.getTerm());
            }
            row.addCell("count", Cell.ROLE_DATA, "count").addContent(facetEntry.getCount());
        }
    }

    private void addDateHistogramToTable(DateHistogramFacet monthlyDownloadsFacet, Division division, String termName, String termDescription) throws WingException {
        List<? extends DateHistogramFacet.Entry> monthlyFacetEntries = monthlyDownloadsFacet.getEntries();

        if(monthlyFacetEntries.size() == 0) {
            division.addPara("Empty result set for: "+termName);
            return;
        }

        Table monthlyTable = division.addTable(termName, monthlyFacetEntries.size(), 10);
        monthlyTable.setHead(termDescription);
        Row tableHeaderRow = monthlyTable.addRow(Row.ROLE_HEADER);
        tableHeaderRow.addCell("date", Cell.ROLE_HEADER,null).addContent(T_dateHeader);
        tableHeaderRow.addCell("count", Cell.ROLE_HEADER,null).addContent(T_count);

        for(DateHistogramFacet.Entry histogramEntry : monthlyFacetEntries) {
            Row dataRow = monthlyTable.addRow();
            Date facetDate = new Date(histogramEntry.getTime());
            dataRow.addCell("date", Cell.ROLE_DATA,"date").addContent(dateFormat.format(facetDate));
            dataRow.addCell("count", Cell.ROLE_DATA,"count").addContent("" + histogramEntry.getCount());
        }
    }
    
    private String getOwningText(DSpaceObject dso) {
        switch (dso.getType()) {
            case Constants.ITEM:
                return "owningItem";
            case Constants.COLLECTION:
                return "owningColl";
            case Constants.COMMUNITY:
                return "owningComm";
            default:
                return "";
        }
    }
    
    private String getFirstMetadataValue(Item item, String metadataKey) {
        DCValue[] dcValue = item.getMetadata(metadataKey);
        if(dcValue.length > 0) {
            return dcValue[0].value;
        } else {
            return "";
        }
    }
}
