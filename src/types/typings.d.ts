/* eslint-disable @typescript-eslint/ban-types */
import 'mongoose';

declare module 'mongoose' {
  interface PaginateOptions {
    sortBy?: 'desc' | 'asc';
    populate?: string;
    limit?: number;
    page?: number;
  }

  interface PaginateResult<T> {
    results: T[];
    page: number;
    limit: number;
    totalPages: number;
    totalResults: number;
  }

  interface PaginateModel<
    TRawDocType,
    TQueryHelpers = {},
    TInstanceMethods = {},
    TVirtuals = {},
    THydratedDocumentType = HydratedDocument<TRawDocType, TVirtuals & TInstanceMethods, TQueryHelpers>,
    TSchema = {},
  > extends Model<TRawDocType, TQueryHelpers, TInstanceMethods, TVirtuals, THydratedDocumentType, TSchema> {
    paginate(filter: FilterQuery<TRawDocType>, options: PaginateOptions): Promise<PaginateResult<TRawDocType>>;
  }
}
